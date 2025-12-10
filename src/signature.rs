// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::missing_safety_doc)]
use anyhow::Context as _;
use libc::{c_char, c_int, size_t};
use openpgp::cert::prelude::*;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{LiteralWriter, Message, Signer};
use openpgp::KeyHandle;
use sequoia_cert_store::{Store as _, StoreUpdate as _};
use sequoia_openpgp as openpgp;
use sequoia_policy_config::ConfiguredStandardPolicy;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::Arc;

use crate::{set_error_from, SequoiaError};

pub struct SequoiaMechanism<'a> {
    keystore: Option<sequoia_keystore::Keystore>,
    certstore: Arc<sequoia_cert_store::CertStore<'a>>,
    policy: StandardPolicy<'a>,
}

impl<'a> SequoiaMechanism<'a> {
    fn from_directory(dir: Option<impl AsRef<Path>>) -> Result<Self, anyhow::Error> {
        let home_path = dir.map(|s| s.as_ref().to_path_buf());
        let sequoia_home = sequoia_directories::Home::new(home_path)?;

        let keystore_dir = sequoia_home.data_dir(sequoia_directories::Component::Keystore);
        let context = sequoia_keystore::Context::configure()
            .home(&keystore_dir)
            // Coverage: .build() can never fail if .home() is set.
            .build()?;
        let keystore = sequoia_keystore::Keystore::connect(&context)?;

        let certstore_dir = sequoia_home.data_dir(sequoia_directories::Component::CertD);
        fs::create_dir_all(&certstore_dir)?;
        // Coverage: CertStore::open currently never fails.
        let certstore = sequoia_cert_store::CertStore::open(&certstore_dir)?;

        // Coverage: To trigger this failure, we would need to set ConfiguredStandardPolicy::ENV_VAR
        // but that’s not safe to do in multi-threaded tests (or to overwrite the system-wide config file).
        let policy = crypto_policy()?;

        Ok(Self {
            keystore: Some(keystore),
            certstore: Arc::new(certstore),
            policy,
        })
    }

    fn ephemeral() -> Result<Self, anyhow::Error> {
        let certstore = Arc::new(sequoia_cert_store::CertStore::empty());
        // Coverage: To trigger this failure, we would need to set ConfiguredStandardPolicy::ENV_VAR
        // but that’s not safe to do in multi-threaded tests (or to overwrite the system-wide config file).
        let policy = crypto_policy()?;
        Ok(Self {
            keystore: None,
            certstore,
            policy,
        })
    }

    fn import_keys(&mut self, blob: &[u8]) -> Result<SequoiaImportResult, anyhow::Error> {
        let mut key_handles = vec![];
        for r in CertParser::from_bytes(blob)? {
            // NOTE that we might have successfully imported something by now;
            // in that case we just return an error and don't report what we have imported.
            // That's fine for containers/image, which creates an one-use ephemeral mechanism
            // and imports keys into it, i.e. there is no benefit in handling partial success specially.
            let cert = r.context("Error parsing certificate")?;

            key_handles.push(CString::new(cert.fingerprint().to_hex().as_bytes()).unwrap());
            self.certstore
                .update(Arc::new(sequoia_cert_store::LazyCert::from(cert)))?;
        }
        Ok(SequoiaImportResult { key_handles })
    }

    fn sign(
        &mut self,
        key_handle: &str,
        password: Option<&str>,
        data: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let primary_key_handle: KeyHandle = key_handle.parse()?; // FIXME: For gpgme, allow lookup by user ID? grep_userid, or what is the compatible semantics?
        let certs = self
            .certstore
            .lookup_by_cert(&primary_key_handle)
            .with_context(|| format!("Failed to look up {key_handle} in certificate store"))?;
        if certs.len() != 1 {
            // This should not happen when looking up by fingerprint, lookup_by_cert documentation says
            // > The caller may assume that looking up a fingerprint returns at
            // > most one certificate.
            // and the implementation merges certificates with the same fingerprint.
            //
            // This _is_ reachable by using a key ID (not a fingerprint) that matches multiple fingerprints.
            // In such a situation, we want to fail: We need the user to be precise about which key
            // we should be signing with.
            //
            // The c/image caller documents the parameter as a fingerprint, but does not restrict the format
            // (it would have to hard-code a copy of Sequoia-PGP’s string format decisions).
            // Alternatively, we could, above, parse primary_key_handle explicitly as a Fingerprint —
            // but for user convenience, letting a key ID through is a bit nicer — and we would _still_
            // want this certs.len() != 1 check, just to be sure.
            return Err(anyhow::anyhow!(
                "Ambiguous input, multiple certificates match {key_handle}"
            ));
        }

        let cert = certs[0]
            .to_cert()
            // Coverage: If LazyCert is not a Cert already, it is a RawCert, and that ensures
            // that it starts with a primary key packet, and contains only expected (or unknown) packets.
            // The Cert parsing requires that only expected packet types are present, and that they
            // "follow the grammar", but it turns out that any sequence that starts with a primary key
            // satisfies that. So, it seems that to_cert should never fail and this error
            // handling path is unreachable.
            .with_context(|| format!("Parsing certificate for {key_handle}"))?;

        let keystore = self.keystore.as_mut().ok_or_else(|| {
            anyhow::anyhow!("Caller error: attempting to sign with an ephemeral mechanism")
        })?;

        let mut key: Option<sequoia_keystore::Key> = None;
        let mut rejected_key_errors: Vec<String> = vec![];
        let ka = cert
            .with_policy(&self.policy, None)
            .with_context(|| format!("No acceptable signing key for {key_handle}"))?;
        for ka in ka.keys().for_signing() {
            if ka.alive().is_err() {
                rejected_key_errors.push(format!("key {} is expired", ka.key().fingerprint()));
            } else if matches!(
                ka.revocation_status(),
                openpgp::types::RevocationStatus::Revoked(_)
            ) {
                rejected_key_errors.push(format!("key {} is revoked", ka.key().fingerprint()));
            } else if !ka.key().pk_algo().is_supported() {
                rejected_key_errors
                    .push(format!("key {} is not supported", ka.key().fingerprint()));
            } else {
                // Coverage: find_key() never fails.
                let mut keys = keystore.find_key(ka.key().key_handle())?;
                if keys.is_empty() {
                    rejected_key_errors.push(format!(
                        "private key for key {} not found",
                        ka.key().fingerprint()
                    ));
                } else {
                    // sq might try all elements of keys — but only if the user aborts passphrase prompting.
                    // We have no way to associate the provided password with a specific subkey, so assume
                    // it is intended for the first one, to behave predictably.
                    key = Some(keys.swap_remove(0));
                    break; // We are done.
                }
            }
        }
        let mut key = match key {
            Some(key) => key,
            None => {
                if !rejected_key_errors.is_empty() {
                    return Err(anyhow::anyhow!(
                        "No acceptable signing key for {key_handle}: {}",
                        rejected_key_errors.join(", ")
                    ));
                } else {
                    // ka.keys().for_signing() only returns keys with the signing flag,
                    // and we found none. (The OpenPGP RFC seems not to make it mandatory
                    // to include the "key flags" subpacket?! Anyway, this is consistent with
                    // (sq sign).)
                    return Err(anyhow::anyhow!("Key {key_handle} does not support signing"));
                }
            }
        };

        if let Some(password) = password {
            key.unlock(password.into())?;
        }

        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            // Coverage: Signer::new() never fails.
            let message = Signer::new(message, &mut key)?
                // Coverage: Signer::build() could fail
                // - With a caller-chosen unsupported hash algorithm (not our case)
                // - If random number generation fails (possible)
                // - If the key in the signer used an unimplemented version (no way to create that)
                // - If writing failed (impossible when writing to memory)
                .build()?;
            // Coverage: LiteralWriter::build() could fail if writing failed (impossible when writing to memory)
            let mut message = LiteralWriter::new(message).build()?;
            // Coverage: This could fail only if writing failed (impossible when writing to memory)
            message.write_all(data)?;
            message.finalize()?;
        }
        Ok(sink)
    }

    /// Verifies a signature against _any_ public key known to the mechanism,
    /// and returns the signed contents, along with the signing key’s (primary) fingerprint, on success.
    ///
    /// Note that this does not implement the web of trust, or any other policy.
    fn verify(&mut self, signature: &[u8]) -> Result<SequoiaVerificationResult, anyhow::Error> {
        let h = Helper {
            certstore: self.certstore.clone(),
            signer: Default::default(),
        };

        // Coverage: VerifierBuilder::from_bytes (via VerifierBuilder::new) never fails.
        let mut v = VerifierBuilder::from_bytes(signature)?.with_policy(&self.policy, None, h)?;
        let mut content = Vec::new();
        v.read_to_end(&mut content)?;

        assert!(v.message_processed());

        match &v.helper_ref().signer {
            Some(signer) => Ok(SequoiaVerificationResult {
                content,
                signer: CString::new(signer.fingerprint().to_hex().as_bytes()).unwrap(),
            }),
            None => Err(anyhow::anyhow!("No valid signer")), // Coverage: Should not happen, Helper should have rejected this.
        }
    }
}

struct Helper<'a> {
    certstore: Arc<sequoia_cert_store::CertStore<'a>>,
    signer: Option<openpgp::Cert>,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut certs = Vec::new();
        for id in ids {
            match self.certstore.lookup_by_cert_or_subkey(id) {
                Ok(matches) => {
                    for lc in matches {
                        // Coverage: lc.to_cert() should never fail for ephemeral SequoiaMechanism, where the in-memory cert store always creates
                        // a LazyCert from a parsed Cert. It could fail for non-ephemeral contexts, where the LazyCert typically originates
                        // as RawCert and the parsed Cert would be created here — but see the discusison of LazyCert::to_cert() in
                        // SigningMechanism::sign(), it seems that this can not actually fail.
                        certs.push(lc.to_cert()?.clone());
                    }
                }
                Err(e) => {
                    if let Some(sequoia_cert_store::store::StoreError::NotFound(_)) =
                        e.downcast_ref()
                    {
                        // Don’t immediately abort, maybe can verify the signature with some other key.
                    } else {
                        return Err(e);
                    }
                }
            };
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let mut signature_errors: Vec<String> = Vec::new();
        for layer in structure {
            match layer {
                MessageLayer::Compression { algo: _ } => (),
                MessageLayer::Encryption {
                    sym_algo: _,
                    aead_algo: _,
                } => {
                    // Coverage: MessageLayer::Encryption is only created when the message parser is invoked using a DecryptorBuilder,
                    // not using a VerifierBuilder like we do.
                    return Err(anyhow::anyhow!(
                        "internal error: MessageLayer::Encryption should never have happened"
                    ));
                }
                MessageLayer::SignatureGroup { ref results } => {
                    for result in results {
                        match result {
                            Ok(good_checksum) => {
                                // NOTE: We are not imposing any trust policy - as long as a public key is found,
                                // this succeeds and the key’s fingerprint is returned to the caller.
                                // This is fine for the expected user, which constructs an ephemeral mechanism
                                // and imports only the keys trusted in that situation — but it might not be suitable
                                // for more general use cases.
                                self.signer = Some(good_checksum.ka.cert().to_owned());
                                return Ok(());
                            }
                            Err(verification_error) => {
                                signature_errors.push(pretty_error(verification_error));
                            }
                        }
                    }
                }
            }
        }
        let err = match signature_errors.len() {
            0 => anyhow::anyhow!("No valid signature"),
            1 => anyhow::anyhow!("{}", &signature_errors[0]),
            _ => anyhow::anyhow!(
                "Multiple signature errors:\n{}",
                signature_errors.join("\n")
            ),
        };
        Err(err)
    }
}

fn pretty_error_chain(err: &anyhow::Error) -> String {
    let causes = err
        .chain()
        .skip(1)
        .map(|cause| format!("because: {cause}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("         {err}\n{causes}") // align err to "because: " length
}

fn pretty_error(verification_error: &VerificationError) -> String {
    fn indent_error_chain(err: &anyhow::Error) -> String {
        pretty_error_chain(err)
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    use openpgp::parse::stream::VerificationError::*;
    match verification_error {
        MissingKey { sig, .. } => format!("Missing key {:X}", sig.get_issuers().first().unwrap()),
        UnboundKey { cert, error, .. } => format!(
            "Signing key on {:X} is not bound:\n{}",
            cert.fingerprint(),
            indent_error_chain(error)
        ),
        BadKey { ka, error, .. } => format!(
            "Signing key on {:X} is bad:\n{}",
            ka.cert().fingerprint(),
            indent_error_chain(error)
        ),
        BadSignature { error, .. } => format!("Bad signature:\n{}", indent_error_chain(error)),
        MalformedSignature { error, .. } => {
            format!("Signature is malformed:\n{}", indent_error_chain(error))
        }
        UnknownSignature { sig, .. } => {
            format!("Unknown signature:\n{}", indent_error_chain(sig.error()))
        }
        _ => verification_error.to_string(),
    }
}

/// Creates a StandardPolicy with the policy we desire, primarily based on the system’s configuration.
fn crypto_policy<'a>() -> Result<StandardPolicy<'a>, anyhow::Error> {
    let mut policy = ConfiguredStandardPolicy::new();
    // Coverage: To trigger this failure, we would need to set ConfiguredStandardPolicy::ENV_VAR
    // but that’s not safe to do in multi-threaded tests (or to overwrite the system-wide config file).
    policy.parse_default_config()?;
    Ok(policy.build())
}

pub struct SequoiaSignature {
    data: Vec<u8>,
}

pub struct SequoiaVerificationResult {
    content: Vec<u8>,
    signer: CString,
}

#[derive(Default)]
pub struct SequoiaImportResult {
    key_handles: Vec<CString>,
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_mechanism_new_from_directory<'a>(
    dir_ptr: *const c_char,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaMechanism<'a> {
    let c_dir = if dir_ptr.is_null() {
        // Coverage: Testing this might affect users’ primary configuration — or we would have
        // to set $HOME, which is not safe to do in multi-threaded tests.
        None
    } else {
        Some(CStr::from_ptr(dir_ptr))
    };
    let os_dir = c_dir.map(|s| OsStr::from_bytes(s.to_bytes()));
    match SequoiaMechanism::from_directory(os_dir) {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_mechanism_new_ephemeral<'a>(
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaMechanism<'a> {
    match SequoiaMechanism::ephemeral() {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            // Coverage: To trigger this failure, we would need to set ConfiguredStandardPolicy::ENV_VAR
            // but that’s not safe to do in multi-threaded tests (or to overwrite the system-wide config file).
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_mechanism_free(mechanism_ptr: *mut SequoiaMechanism) {
    drop(Box::from_raw(mechanism_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_signature_free(signature_ptr: *mut SequoiaSignature) {
    drop(Box::from_raw(signature_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_signature_get_data(
    signature_ptr: *const SequoiaSignature,
    data_len: *mut size_t,
) -> *const u8 {
    assert!(!signature_ptr.is_null());
    *data_len = (*signature_ptr).data.len();
    (*signature_ptr).data.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verification_result_free(
    result_ptr: *mut SequoiaVerificationResult,
) {
    assert!(!result_ptr.is_null());
    drop(Box::from_raw(result_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verification_result_get_content(
    result_ptr: *const SequoiaVerificationResult,
    data_len: *mut size_t,
) -> *const u8 {
    assert!(!result_ptr.is_null());
    *data_len = (*result_ptr).content.len();
    (*result_ptr).content.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verification_result_get_signer(
    result_ptr: *const SequoiaVerificationResult,
) -> *const c_char {
    assert!(!result_ptr.is_null());
    (*result_ptr).signer.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_sign(
    mechanism_ptr: *mut SequoiaMechanism,
    key_handle_ptr: *const c_char,
    password_ptr: *const c_char,
    data_ptr: *const u8,
    data_len: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaSignature {
    assert!(!mechanism_ptr.is_null());
    assert!(!key_handle_ptr.is_null());
    assert!(!data_ptr.is_null());

    let key_handle = match CStr::from_ptr(key_handle_ptr).to_str() {
        Ok(key_handle) => key_handle,
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return ptr::null_mut();
        }
    };

    let password = if password_ptr.is_null() {
        None
    } else {
        match CStr::from_ptr(password_ptr).to_str() {
            Ok(password) => Some(password),
            Err(e) => {
                set_error_from(err_ptr, e.into());
                return ptr::null_mut();
            }
        }
    };

    let data = slice::from_raw_parts(data_ptr, data_len);
    match (*mechanism_ptr).sign(key_handle, password, data) {
        Ok(signature) => Box::into_raw(Box::new(SequoiaSignature { data: signature })),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_verify(
    mechanism_ptr: *mut SequoiaMechanism,
    signature_ptr: *const u8,
    signature_len: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaVerificationResult {
    assert!(!mechanism_ptr.is_null());

    let signature = slice::from_raw_parts(signature_ptr, signature_len);
    match (*mechanism_ptr).verify(signature) {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_result_free(result_ptr: *mut SequoiaImportResult) {
    drop(Box::from_raw(result_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_result_get_count(
    result_ptr: *const SequoiaImportResult,
) -> size_t {
    assert!(!result_ptr.is_null());

    (*result_ptr).key_handles.len()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_result_get_content(
    result_ptr: *const SequoiaImportResult,
    index: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *const c_char {
    assert!(!result_ptr.is_null());

    if index >= (*result_ptr).key_handles.len() {
        set_error_from(err_ptr, anyhow::anyhow!("No matching key handle"));
        return ptr::null();
    }
    let key_handle = &(&(*result_ptr)).key_handles[index];
    key_handle.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn sequoia_import_keys(
    mechanism_ptr: *mut SequoiaMechanism,
    blob_ptr: *const u8,
    blob_len: size_t,
    err_ptr: *mut *mut SequoiaError,
) -> *mut SequoiaImportResult {
    assert!(!mechanism_ptr.is_null());

    let blob = slice::from_raw_parts(blob_ptr, blob_len);
    match (*mechanism_ptr).import_keys(blob) {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

// SequoiaLogLevel is a C-compatible version of log::Level.
#[derive(Eq, PartialEq, Debug)]
#[repr(C)]
/// cbindgen:rename-all=ScreamingSnakeCase
/// cbindgen:prefix-with-name
pub enum SequoiaLogLevel {
    Unknown,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

// SequoiaLogger implements log::Log.
struct SequoiaLogger {
    consumer: unsafe extern "C" fn(level: SequoiaLogLevel, message: *const c_char),
}

impl log::Log for SequoiaLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let level = match record.level() {
            log::Level::Error => SequoiaLogLevel::Error,
            log::Level::Warn => SequoiaLogLevel::Warn,
            log::Level::Info => SequoiaLogLevel::Info,
            log::Level::Debug => SequoiaLogLevel::Debug,
            log::Level::Trace => SequoiaLogLevel::Trace,
        };
        let text = match CString::new(record.args().to_string()) {
            Ok(text) => text,
            Err(_) => {
                return;
            }
        };
        unsafe { (self.consumer)(level, text.as_ptr()) };
    }

    fn flush(&self) {}
}

// sequoia_set_logger_consumer sets the process-wide Rust logger to the provided simple string consumer.
// More sophisticated logging interfaces may be added in the future as an alternative.
// Note that the logger is a per-process global; it is up to the caller to coordinate.
#[no_mangle]
pub unsafe extern "C" fn sequoia_set_logger_consumer(
    consumer: unsafe extern "C" fn(level: SequoiaLogLevel, message: *const c_char),
    err_ptr: *mut *mut SequoiaError,
) -> c_int {
    let logger = SequoiaLogger { consumer };
    match log::set_boxed_logger(Box::new(logger)) {
        // Leaks the logger, but this is explicitly an once-per-process API.
        //
        // Coverage: set_boxed_logger can only succeed once per process, and internally,
        // sequoia-keystore does env_logger::Builder::from_default_env().try_init(),
        // i.e. unrelated test cases can set the logger, and we can’t reliably test the success path.
        Ok(_) => {}
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return -1;
        }
    }

    log::set_max_level(log::LevelFilter::Trace); // We’ll let the consumer do the filtering, if any.
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    use log::Log as _;
    use openpgp::serialize::SerializeInto as _;

    const TEST_KEY: &[u8] = include_bytes!("./data/no-passphrase.pub");
    const TEST_KEY_FINGERPRINT: &str = "50DDE898DF4E48755C8C2B7AF6F908B6FA48A229";
    const TEST_KEY_WITH_PASSPHRASE: &[u8] = include_bytes!("./data/with-passphrase.pub");
    // Note that the tests never unlock this key, because that would affect per-process state
    // and interfere with any other tests referring to this key.
    const TEST_KEY_WITH_PASSPHRASE_FINGERPRINT: &str = "1F5825285B785E1DB13BF36D2D11A19ABA41C6AE";
    const INVALID_PUBLIC_KEY_BLOB: &[u8] = b"\xC6\x09this is not a valid public key";

    #[test]
    fn primary_workflow() {
        // The typical successful usage of this library.
        let input = b"Hello, world!";

        let signed = with_c_fixture_mechanism(|m1| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            let c_fingerprint = CString::new(TEST_KEY_FINGERPRINT).unwrap();
            let sig = unsafe {
                super::sequoia_sign(
                    m1,
                    c_fingerprint.as_ptr(),
                    ptr::null(),
                    input.as_ptr(),
                    input.len(),
                    &mut err_ptr,
                )
            };
            assert!(!sig.is_null());
            assert!(err_ptr.is_null());
            let mut sig_size: size_t = 0;
            let c_sig_data = unsafe { sequoia_signature_get_data(sig, &mut sig_size) };
            let sig_slice = unsafe { slice::from_raw_parts(c_sig_data, sig_size) };
            let signed = sig_slice.to_vec();
            unsafe { sequoia_signature_free(sig) };

            signed
        });

        with_c_ephemeral_mechanism(|m2| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            // With no public key, verification should fail
            let res = unsafe { sequoia_verify(m2, signed.as_ptr(), signed.len(), &mut err_ptr) };
            assert!(res.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
            err_ptr = ptr::null_mut();

            let mut fingerprints: Vec<String> = Vec::new();
            {
                let import_result = unsafe {
                    super::sequoia_import_keys(m2, TEST_KEY.as_ptr(), TEST_KEY.len(), &mut err_ptr)
                };
                assert!(!import_result.is_null());
                assert!(err_ptr.is_null());
                let count = unsafe { sequoia_import_result_get_count(import_result) };
                for i in 0..count {
                    let c_fingerprint = unsafe {
                        super::sequoia_import_result_get_content(import_result, i, &mut err_ptr)
                    };
                    let fingerprint = unsafe { CStr::from_ptr(c_fingerprint) };
                    fingerprints.push(fingerprint.to_str().unwrap().to_owned());
                }
                unsafe { sequoia_import_result_free(import_result) };
            }
            assert_eq!(fingerprints.len(), 1);
            assert_eq!(fingerprints[0], TEST_KEY_FINGERPRINT);

            {
                let res =
                    unsafe { sequoia_verify(m2, signed.as_ptr(), signed.len(), &mut err_ptr) };
                assert!(!res.is_null());
                assert!(err_ptr.is_null());

                let mut contents_size: size_t = 0;
                let c_contents =
                    unsafe { sequoia_verification_result_get_content(res, &mut contents_size) };
                let contents_slice = unsafe { slice::from_raw_parts(c_contents, contents_size) };
                assert_eq!(contents_slice, input);

                let c_signer = unsafe { sequoia_verification_result_get_signer(res) };
                let signer = unsafe { CStr::from_ptr(c_signer) };
                assert_eq!(signer.to_str().unwrap(), TEST_KEY_FINGERPRINT);

                unsafe { sequoia_verification_result_free(res) };
            }
        });
    }

    #[test]
    fn sequoia_mechanism_from_directory() {
        // Success is tested in primary_workflow().

        // Error preparing home directory path in sequoia_directories::Home::new:
        // Failures to access an absolute path are ignored, but a relative path triggers
        // an attempt to create all parent directories. If one of them is an unresolvable symlink
        // the whole operation fails.
        {
            let original_dir = std::env::current_dir().unwrap();
            let temp_dir = tempfile::tempdir().unwrap();
            std::env::set_current_dir(&temp_dir).unwrap();
            std::os::unix::fs::symlink("/var/empty/this/does/not/exist", "unreachable-symlink")
                .unwrap();
            let res =
                SequoiaMechanism::from_directory(Some(Path::new("unreachable-symlink/subdir/dir")));
            assert!(res.is_err());
            std::env::set_current_dir(original_dir).unwrap();
            temp_dir.close().unwrap();
        }

        // Error creating a keystore:
        // Use a non-directory component in the home directory path (merely using a non-existent path
        // could succeed when running as root, auto-creating the parents).
        let res =
            SequoiaMechanism::from_directory(Some(Path::new("/dev/null/this/does/not/exist")));
        assert!(res.is_err());

        // Error creating a certstore directory:
        // Place a dangling symlink at the certstore path.
        {
            let temp_dir = tempfile::tempdir().unwrap();
            let certstore_dir = sequoia_directories::Home::new(temp_dir.path().to_path_buf())
                .unwrap()
                .data_dir(sequoia_directories::Component::CertD);
            fs::create_dir_all(certstore_dir.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink("/var/empty/this/does/not/exist", certstore_dir).unwrap();
            let res = SequoiaMechanism::from_directory(Some(temp_dir.path()));
            assert!(res.is_err());
            temp_dir.close().unwrap();
        }
    }

    #[test]
    fn sequoia_mechanism_new_from_directory() {
        // Success is tested in primary_workflow().

        // Failure:
        // Use a non-directory component in the home directory path (merely using a non-existent path
        // could succeed when running as root, auto-creating the parents).
        let mut err_ptr: *mut SequoiaError = ptr::null_mut();
        let c_sequoia_home = CString::new("/dev/null/this/does/not/exist").unwrap();
        let m = unsafe {
            super::sequoia_mechanism_new_from_directory(c_sequoia_home.as_ptr(), &mut err_ptr)
        };
        assert!(m.is_null());
        assert!(!err_ptr.is_null());
        unsafe { crate::sequoia_error_free(err_ptr) };
    }

    #[test]
    fn sign() {
        // Success is tested in primary_workflow().

        fn with_temporary_mechanism<R>(f: impl FnOnce(&mut SequoiaMechanism) -> R) -> R {
            let temp_dir = tempfile::tempdir().unwrap();
            let mut mech = SequoiaMechanism::from_directory(Some(temp_dir.path())).unwrap();
            let res = f(&mut mech);
            temp_dir.close().unwrap();
            res
        }

        // Successful signing with a passphrase:
        // We want to do this on a temporary mechanism, because seqoia-keystore::server::Servers maintains
        // a per-process singleton for each home directory; so, unlocking a key is permanent.
        // OTOH we want to also test not unlocking, or unlocking with a wrong passphrase — so we need
        // at least two mechanisms, one where unlocking succeeds, one where it fails.
        const LOCAL_PASSPHRASE: &str = "a single-use passphrase";
        let (cert, signature) = with_temporary_mechanism(|mut mech| {
            let (cert, _) = CertBuilder::new()
                .set_primary_key_flags(
                    openpgp::types::KeyFlags::empty()
                        .set_certification()
                        .set_signing(),
                )
                .add_userid("passphrase-protected")
                .set_password(Some(LOCAL_PASSPHRASE.into()))
                .generate()
                .unwrap();
            import_private_key(&mut mech, &cert);
            // Sanity-check that signing without a passphrase fails, first
            let res = mech.sign(&cert.fingerprint().to_hex(), None, b"contents");
            assert!(res.is_err());
            let res = mech.sign(
                &cert.fingerprint().to_hex(),
                Some(LOCAL_PASSPHRASE),
                b"contents",
            );
            let signature = res.expect("signature should be returned");
            (cert, signature)
        });
        let fingerprint = cert.fingerprint();
        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        mech.import_keys(
            cert.strip_secret_key_material()
                .export_to_vec()
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let res = mech.verify(&signature).expect("verify should succeed");
        assert_eq!(res.content, b"contents");
        assert_eq!(res.signer, CString::new(fingerprint.to_hex()).unwrap());

        // Invalid key handle format:
        with_fixture_sequoia_home_locked(|fixture_dir| {
            let mut mech = SequoiaMechanism::from_directory(Some(fixture_dir)).unwrap();
            let res = mech.sign("should-be-hexadecimal", None, b"contents");
            assert!(res.is_err());
        });

        // Key handle not found in certificate store:
        with_fixture_sequoia_home_locked(|fixture_dir| {
            let mut mech = SequoiaMechanism::from_directory(Some(fixture_dir)).unwrap();
            let res = mech.sign(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                None,
                b"contents",
            );
            assert!(res.is_err());
        });

        // We don’t test the case where a key matches multiple certificates.
        // This is reachable by using a key ID (not a fingerprint) that matches multiple fingerprints,
        // we are not going to try generating such a collision. Also, the external c/image API
        // is documented to accept fingerprints, not key IDs (although, actually, key IDs are not rejected).

        // Attempting to sign with an ephemeral mechanism (no keystore):
        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        mech.import_keys(&TEST_KEY).unwrap();
        let res = mech.sign(TEST_KEY_FINGERPRINT, None, b"contents");
        assert!(res.is_err());

        // Trying to sign with a key where even the primary key is invalid (in this case, the binding signature is expired):
        with_temporary_mechanism(|mut mech| {
            let cert = generate_cert_with_expired_self_signature();
            import_private_key(&mut mech, &cert);
            let res = mech.sign(&cert.fingerprint().to_hex(), None, b"contents");
            assert!(res.is_err());
        });

        // Trying to sign with an expired key
        with_temporary_mechanism(|mut mech| {
            // For simplicity, we generate a single-key certificate where the primary
            // key supports signing and is expired.
            let (cert, _) = CertBuilder::new()
                .set_primary_key_flags(
                    openpgp::types::KeyFlags::empty()
                        .set_certification()
                        .set_signing(),
                )
                .add_userid("key expired")
                .set_creation_time(
                    std::time::SystemTime::now()
                        - std::time::Duration::from_secs(365 * 24 * 60 * 60),
                )
                .set_validity_period(std::time::Duration::from_secs(60 * 60))
                .generate()
                .unwrap();
            import_private_key(&mut mech, &cert);
            let res = mech.sign(&cert.fingerprint().to_hex(), None, b"contents");
            assert!(res.is_err());
        });

        // Trying to sign with a revoked key
        with_temporary_mechanism(|mut mech| {
            let (cert, _) = CertBuilder::new()
                .add_userid("signing subkey revoked")
                .set_creation_time(
                    std::time::SystemTime::now()
                        - std::time::Duration::from_secs(365 * 24 * 60 * 60),
                )
                .add_signing_subkey()
                .generate()
                .unwrap();
            let mut signer = cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()
                .unwrap()
                .into_keypair()
                .unwrap();
            let subkey = cert.keys().subkeys().nth(0).unwrap();
            let sig = SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(openpgp::types::ReasonForRevocation::KeyCompromised, b"")
                .unwrap()
                .build(&mut signer, &cert, subkey.key(), None)
                .unwrap();
            let cert = cert.insert_packets(sig).unwrap().0;
            import_private_key(&mut mech, &cert);
            let res = mech.sign(&cert.fingerprint().to_hex(), None, b"contents");
            assert!(res.is_err());
        });

        // We do not test trying to sign with an unsupported key: that would require creating
        // and importing an ElGamal key somehow.

        // Trying to sign when we have a certificate but not the private key.
        with_temporary_mechanism(|mech| {
            mech.import_keys(TEST_KEY).unwrap();
            let res = mech.sign(TEST_KEY_FINGERPRINT, None, b"contents");
            assert!(res.is_err());
        });

        // Trying to sign using a key which is not capable of signing:
        with_temporary_mechanism(|mut mech| {
            // For simplicity, we generate a single-key certificate where the primary
            // key only supports certification.
            let (cert, _) = CertBuilder::new()
                .add_userid("no signing capability")
                .generate()
                .unwrap();
            import_private_key(&mut mech, &cert);
            let res = mech.sign(&cert.fingerprint().to_hex(), None, b"contents");
            assert!(res.is_err());
        });

        // Trying to sign without providing a required passphrase:
        with_fixture_sequoia_home_locked(|fixture_dir| {
            let mut mech = SequoiaMechanism::from_directory(Some(fixture_dir)).unwrap();
            let res = mech.sign(TEST_KEY_WITH_PASSPHRASE_FINGERPRINT, None, b"contents");
            assert!(res.is_err());
        });

        // Trying to sign with a wrong passphrase:
        with_fixture_sequoia_home_locked(|fixture_dir| {
            let mut mech = SequoiaMechanism::from_directory(Some(fixture_dir)).unwrap();
            let res = mech.sign(
                TEST_KEY_WITH_PASSPHRASE_FINGERPRINT,
                Some("incorrect passphrase"),
                b"contents",
            );
            assert!(res.is_err());
        });
    }

    // generate_cert_with_expired_self_signature is a helper for the sign() test.
    pub fn generate_cert_with_expired_self_signature() -> Cert {
        // This is surprisingly tedious.
        //
        // Ordinarily, CertBuilder.set_validity_period() sets the _key_ validity period;
        // that does not invalidate the validity of the self-signature, and that’s
        // the only thing Cert::with_policy() cares about. (In particular, at least for a primary
        // key, it ignores revoked binding signatures as well as binding signatuers with expired keys).
        // So, this is basically CertBuilder::generate(), specialized for our parameters,
        // with the extra set_signature_validity_period() calls we need.
        let creation_time =
            std::time::SystemTime::now() - std::time::Duration::from_secs(365 * 24 * 60 * 60);

        // Generate & self-sign primary key.
        let mut primary = openpgp::packet::key::Key::V4(
            openpgp::packet::key::Key4::<
                openpgp::packet::key::SecretParts,
                openpgp::packet::key::PrimaryRole,
            >::generate_ecc(true, openpgp::types::Curve::Ed25519)
            .unwrap(),
        );
        primary.set_creation_time(creation_time).unwrap();
        let mut signer = primary.clone().into_keypair().unwrap();

        let our_signature_builder =
            |typ: openpgp::types::SignatureType| -> openpgp::packet::prelude::SignatureBuilder {
                openpgp::packet::prelude::SignatureBuilder::new(typ)
                    .set_signature_creation_time(creation_time)
                    .unwrap()
                    .set_signature_validity_period(std::time::Duration::from_secs(24 * 60 * 60))
                    .unwrap()
                    .set_key_flags(
                        openpgp::types::KeyFlags::empty()
                            .set_certification()
                            .set_signing(),
                    )
                    .unwrap()
            };

        let cert = Cert::try_from(vec![openpgp::Packet::SecretKey(primary.clone())]).unwrap();
        let direct_sig = our_signature_builder(openpgp::types::SignatureType::DirectKey)
            .sign_direct_key(&mut signer, primary.parts_as_public())
            .unwrap();
        let uid = openpgp::packet::UserID::from("expired binding signature");
        let sig = our_signature_builder(openpgp::types::SignatureType::PositiveCertification)
            .set_primary_userid(true)
            .unwrap();
        let uid_signature = uid.bind(&mut signer, &cert, sig).unwrap();
        let cert = cert
            .insert_packets(vec![
                openpgp::Packet::Signature(direct_sig),
                uid.into(),
                uid_signature.into(),
            ])
            .unwrap()
            .0;
        cert
    }

    #[test]
    fn sequoia_sign() {
        // Success is tested in primary_workflow().

        let plaintext = b"contents";

        // Successful signing with a passphrase:
        // See the comment in the sign() test about not unlocking the fixture home directory
        // in tests.
        let (cert, signature) = {
            const LOCAL_PASSPHRASE: &str = "a single-use passphrase";

            let temp_dir = tempfile::tempdir().unwrap();
            let cert = {
                let mut mech = SequoiaMechanism::from_directory(Some(temp_dir.path())).unwrap();

                let (cert, _) = CertBuilder::new()
                    .set_primary_key_flags(
                        openpgp::types::KeyFlags::empty()
                            .set_certification()
                            .set_signing(),
                    )
                    .add_userid("passphrase-protected")
                    .set_password(Some(LOCAL_PASSPHRASE.into()))
                    .generate()
                    .unwrap();
                import_private_key(&mut mech, &cert);
                // Sanity-check that signing without a passphrase fails, first
                let res = mech.sign(&cert.fingerprint().to_hex(), None, plaintext);
                assert!(res.is_err());
                cert
            };
            let signature = with_c_mechanism_from_directory(temp_dir.path(), |mech| {
                let mut err_ptr: *mut SequoiaError = ptr::null_mut();

                let c_fingerprint = CString::new(cert.fingerprint().to_hex()).unwrap();
                let c_passphrase = CString::new(LOCAL_PASSPHRASE).unwrap();
                let sig = unsafe {
                    super::sequoia_sign(
                        mech,
                        c_fingerprint.as_ptr(),
                        c_passphrase.as_ptr(),
                        plaintext.as_ptr(),
                        plaintext.len(),
                        &mut err_ptr,
                    )
                };
                assert!(!sig.is_null());
                assert!(err_ptr.is_null());
                let mut sig_size: size_t = 0;
                let c_sig_data = unsafe { sequoia_signature_get_data(sig, &mut sig_size) };
                let sig_slice = unsafe { slice::from_raw_parts(c_sig_data, sig_size) };
                let signature = sig_slice.to_vec();
                unsafe { sequoia_signature_free(sig) }
                signature
            });
            (cert, signature)
        };
        let fingerprint = cert.fingerprint();
        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        mech.import_keys(
            cert.strip_secret_key_material()
                .export_to_vec()
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let res = mech.verify(&signature).expect("verify should succeed");
        assert_eq!(res.content, plaintext);
        assert_eq!(res.signer, CString::new(fingerprint.to_hex()).unwrap());

        // Invalid UTF-8 in key_handle:
        with_c_fixture_mechanism(|m| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            let c_fingerprint = CString::new(b"invalid UTF-8: \x80\x80").unwrap();
            let res = unsafe {
                super::sequoia_sign(
                    m,
                    c_fingerprint.as_ptr(),
                    ptr::null(),
                    plaintext.as_ptr(),
                    plaintext.len(),
                    &mut err_ptr,
                )
            };
            assert!(res.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
        });

        // Invalid UTF-8 in password:
        with_c_fixture_mechanism(|m| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            // This key doesn’t require a passphrase at all — we fail anyway, before
            // we could even get the opportunity to determine that.
            let c_fingerprint = CString::new(TEST_KEY_FINGERPRINT).unwrap();
            let c_passphrase = CString::new(b"invalid UTF-8: \x80\x80").unwrap();
            let res = unsafe {
                super::sequoia_sign(
                    m,
                    c_fingerprint.as_ptr(),
                    c_passphrase.as_ptr(),
                    plaintext.as_ptr(),
                    plaintext.len(),
                    &mut err_ptr,
                )
            };
            assert!(res.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
        });

        // Signing failed (in this case, invalid fingerprint):
        with_c_fixture_mechanism(|m| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            let c_fingerprint = CString::new(b"this is not a valid fingerprint").unwrap();
            let res = unsafe {
                super::sequoia_sign(
                    m,
                    c_fingerprint.as_ptr(),
                    ptr::null(),
                    plaintext.as_ptr(),
                    plaintext.len(),
                    &mut err_ptr,
                )
            };
            assert!(res.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
        });
    }

    #[test]
    fn import_keys() {
        // The basic case of import of a single key is tested in primary_workflow().

        // Empty input.
        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech.import_keys(&[]).expect("import should succeed");
        assert!(res.key_handles.is_empty());

        // A valid import of multiple keys.
        let pk1 = &TEST_KEY[..];
        let pk2 = &TEST_KEY_WITH_PASSPHRASE[..];
        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech
            .import_keys(&[pk1, pk2].concat())
            .expect("import should succeed");
        assert_eq!(
            res.key_handles,
            [
                CString::new(TEST_KEY_FINGERPRINT).unwrap(),
                CString::new(TEST_KEY_WITH_PASSPHRASE_FINGERPRINT).unwrap(),
            ],
        );

        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech.import_keys(b"this is not a valid public key");
        // "unexpected EOF": When the input does not look like binary OpenPGP, the code tries to parse it as ASCII-armored,
        // and looks for a BEGIN… header.
        assert!(res.is_err());

        let mut mech = SequoiaMechanism::ephemeral().unwrap();
        let res = mech.import_keys(INVALID_PUBLIC_KEY_BLOB);
        // "Error parsing certificate" Malformed packet: Truncated packet": The input starts with a valid enough OpenPGP packet header.
        assert!(res.is_err());

        // Generally, the certstore.update call should never fail for ephemeral mechanisms; it might fail
        // - if the provided LazyCert can’t be parsed, but we already have a parsed form
        // - on an internal inconsistency of CertStore, if it tries to merge two certificates with different fingerprints
        // but, purely for test purposes, we can trigger a write failure by using a non-ephemeral mechanism
        // (which is not expected to happen in practice).
        if cfg!(unix) {
            let sequoia_home = tempfile::tempdir().unwrap();
            let certstore_dir = sequoia_directories::Home::new(sequoia_home.path().to_path_buf())
                .unwrap()
                .data_dir(sequoia_directories::Component::CertD);
            let mut mech = SequoiaMechanism::from_directory(Some(sequoia_home.path())).unwrap();
            // Forcefully delete the contents of certstore_dir, and replace it with a dangling symlink.
            fs::remove_dir_all(&certstore_dir).unwrap();
            std::os::unix::fs::symlink("/var/empty/this/does/not/exist", &certstore_dir).unwrap();
            let res = mech.import_keys(pk1);
            assert!(res.is_err());
        }
    }

    #[test]
    fn sequoia_import_result_get_content() {
        // Success is tested in primary_workflow().

        // Index out of range
        with_c_ephemeral_mechanism(|m| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            let no_public_key = b"";
            let import_result = unsafe {
                super::sequoia_import_keys(
                    m,
                    no_public_key.as_ptr(),
                    no_public_key.len(),
                    &mut err_ptr,
                )
            };
            assert!(!import_result.is_null());
            assert!(err_ptr.is_null());
            let count = unsafe { sequoia_import_result_get_count(import_result) };
            assert_eq!(count, 0);

            let c_fingerprint = unsafe {
                super::sequoia_import_result_get_content(import_result, 9999, &mut err_ptr)
            };
            assert!(c_fingerprint.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
            // err_ptr = ptr::null_mut();

            unsafe { sequoia_import_result_free(import_result) };
        });
    }

    #[test]
    fn sequoia_import_keys_invalid_public_key() {
        // Success is tested in primary_workflow().

        // Import failed.
        with_c_ephemeral_mechanism(|m| {
            let mut err_ptr: *mut SequoiaError = ptr::null_mut();

            let import_result = unsafe {
                super::sequoia_import_keys(
                    m,
                    INVALID_PUBLIC_KEY_BLOB.as_ptr(),
                    INVALID_PUBLIC_KEY_BLOB.len(),
                    &mut err_ptr,
                )
            };
            assert!(import_result.is_null());
            assert!(!err_ptr.is_null());
            unsafe { crate::sequoia_error_free(err_ptr) };
        });
    }

    #[test]
    fn verify() {
        // Basic success is tested in primary_workflow().

        // Empty signature
        let mut m = SequoiaMechanism::ephemeral().unwrap();
        m.import_keys(TEST_KEY).unwrap();
        let res = m.verify(b"");
        assert!(res.is_err());

        // A very large signature, where verification happens in read_to_end, not already in VerifierBuilder::with_policy.
        // Success:
        let large_signature = with_fixture_sequoia_home_locked(|fixture_dir| {
            let mut m = SequoiaMechanism::from_directory(Some(fixture_dir.as_path())).unwrap();
            let large_contents: Vec<u8> = vec![0; 2 * openpgp::parse::stream::DEFAULT_BUFFER_SIZE];
            let large_signature = m.sign(TEST_KEY_FINGERPRINT, None, &large_contents).unwrap();
            let res = m.verify(&large_signature).expect("verify should succeed");
            assert_eq!(res.content, large_contents);
            large_signature
        });
        // Failure: (using a mechanism which doesn’t trust the key)
        let mut m = SequoiaMechanism::ephemeral().unwrap();
        let res = m.verify(&large_signature);
        assert!(res.is_err());
    }

    #[test]
    fn verification_helper_get_certs() {
        // Success is tested in primary_workflow().

        let valid_signature = include_bytes!("./data/sequoia.signature");

        // Certificate not found
        let mut m = SequoiaMechanism::ephemeral().unwrap(); // No public keys
        let res = m.verify(valid_signature);
        assert!(res.is_err());

        // Other error:
        // Generally, the certstore.lookup_by_cert_or_subkey call should only fail by reporting that
        // nothing was found.
        // We also can’t very easily trigger a read I/O error, because sequoia-cert-store::store::certd::CertD
        // reads all files on creation already.
        // So, *sigh*, mock a failing cert store.
        let mut store = sequoia_cert_store::CertStore::empty();
        store.add_backend(
            Box::new(FailingCertStore {}),
            sequoia_cert_store::AccessMode::Always,
        );
        let mut m = SequoiaMechanism {
            keystore: None,
            certstore: Arc::new(store),
            policy: crypto_policy().unwrap(),
        };
        let res = m.verify(valid_signature);
        assert!(res.is_err());
    }

    // FailingCertStore exists for the verification_helper_get_certs test.
    struct FailingCertStore {}
    impl<'a> sequoia_cert_store::Store<'a> for FailingCertStore {
        fn lookup_by_cert(
            &self,
            _: &KeyHandle,
        ) -> openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'a>>>> {
            Err(anyhow::anyhow!("test error"))
        }
        fn lookup_by_cert_or_subkey(
            &self,
            _: &KeyHandle,
        ) -> openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'a>>>> {
            Err(anyhow::anyhow!("test error"))
        }
        fn select_userid(
            &self,
            _: &sequoia_cert_store::store::UserIDQueryParams,
            _: &str,
        ) -> openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'a>>>> {
            Err(anyhow::anyhow!("test error"))
        }
        fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = openpgp::Fingerprint> + 'b> {
            Box::new(std::iter::empty())
        }
    }

    #[test]
    fn verification_helper_check() {
        // Basic success is tested in primary_workflow().

        // Signature uses a compressed data packet (as GnuPG does), and it is valid:
        let mut m = SequoiaMechanism::ephemeral().unwrap();
        m.import_keys(include_bytes!("./data/public-key.gpg"))
            .unwrap();
        let res = m
            .verify(include_bytes!("./data/invalid-blob.signature"))
            .expect("verify should succeed");
        assert_eq!(res.content, b"This is not JSON\n");
        assert_eq!(
            res.signer,
            CString::new("08CD26E446E2E95249B7A405E932F44B23E8DD43").unwrap()
        );

        // Encrypted, but unsigned, data:
        // This does not create MessageLayer::Encryption, the code never creates that when verifying
        // (we’d have to explicitly be decrypting, not verifying).
        let mut m = SequoiaMechanism::ephemeral().unwrap();
        let res = m.verify(include_bytes!("./data/unsigned-encrypted.signature"));
        // "Malformed Message: Malformed OpenPGP message" because encrypted data is only processed when decrypting, and ignored by Verifier.
        assert!(res.is_err());

        // Literal data with no signature:
        let mut m = SequoiaMechanism::ephemeral().unwrap();
        let res = m.verify(include_bytes!("./data/unsigned-literal.signature"));
        assert!(res.is_err()); // "No valid signature" by our Helper

        // Double-signed signature:
        // Created using
        //  let message = Message::new(&mut sink);
        //  let message = Signer::new(message, &mut key1).unwrap().build().unwrap();
        //  let message = Signer::new(message, &mut key2).unwrap().build().unwrap();
        //  let mut message = LiteralWriter::new(message).build().unwrap();
        //  message.write_all(b"double-signed").unwrap();
        //  message.finalize().unwrap();
        // with key1 and key2 being TEST_KEY_FINGERPRINT_WITH_PASSPHRASE.
        let double_signed_signature = include_bytes!("./data/double-signed.signature");
        let mut m = SequoiaMechanism::ephemeral().unwrap();
        let res = m.verify(double_signed_signature);
        assert!(res.is_err()); // "Multiple signature errors: [Missing key …, Missing key …]" by our Helper
        m.import_keys(TEST_KEY_WITH_PASSPHRASE).unwrap();
        m.verify(double_signed_signature)
            .expect("verify should succeed");
    }

    #[test]
    fn sequoia_logger() {
        // See the discussion in sequoia_set_logger_consumer below explaining that we can’t test
        // logging end-to-end.

        struct Recording {
            level: Option<SequoiaLogLevel>,
            message: Option<String>,
        }
        // RECORDED allows logging _one_ message, and records the data for later inspection.
        // This must be static because the "consumer" parameter is not accompanied
        // with any way to pass context to the C closure.
        static RECORDED: std::sync::Mutex<Recording> = std::sync::Mutex::new(Recording {
            level: None,
            message: None,
        });

        extern "C" fn record(level: SequoiaLogLevel, message: *const c_char) {
            let c_message = unsafe { CStr::from_ptr(message) };
            let mut recorded = RECORDED.lock().unwrap();
            assert!(recorded.level.is_none());
            assert!(recorded.message.is_none());
            recorded.level = Some(level);
            recorded.message = Some(c_message.to_str().unwrap().to_owned());
        }
        fn recorded() -> (Option<SequoiaLogLevel>, Option<String>) {
            let mut recorded = RECORDED.lock().unwrap();
            (recorded.level.take(), recorded.message.take())
        }

        // Log::enabled
        let logger = SequoiaLogger { consumer: record };
        for mb in [
            // A random set of examples, the implementation ignores the value.
            &mut log::MetadataBuilder::new(),
            log::MetadataBuilder::new().level(log::Level::Info),
            log::MetadataBuilder::new()
                .level(log::Level::Trace)
                .target("some target"),
        ] {
            let res = logger.enabled(&mb.build());
            assert_eq!(res, true);
            assert_eq!(recorded(), (None, None));
        }

        // Log::log
        for (rust_level, c_level) in [
            (log::Level::Error, SequoiaLogLevel::Error),
            (log::Level::Warn, SequoiaLogLevel::Warn),
            (log::Level::Info, SequoiaLogLevel::Info),
            (log::Level::Debug, SequoiaLogLevel::Debug),
            (log::Level::Trace, SequoiaLogLevel::Trace),
        ] {
            let record = log::RecordBuilder::new()
                .args(format_args!("text"))
                .level(rust_level)
                .build();
            logger.log(&record);
            assert_eq!(recorded(), (Some(c_level), Some("text".into())));
        }
        // Entries with embedded NULs are discarded
        let record = log::RecordBuilder::new()
            .args(format_args!("NUL:'\0'"))
            .level(log::Level::Info)
            .build();
        logger.log(&record);
        assert_eq!(recorded(), (None, None));

        // Log::flush
        logger.flush();
        assert_eq!(recorded(), (None, None));
        logger.log(&log::RecordBuilder::new().args(format_args!("text")).build());
        // Here we don't care about the value, we just want known state to verify that flush() does not call the callback.
        _ = recorded();
        logger.flush();
        assert_eq!(recorded(), (None, None));
    }

    #[test]
    fn sequoia_set_logger_consumer() {
        // set_boxed_logger can only succeed once per process, and internally,
        // sequoia-keystore does env_logger::Builder::from_default_env().try_init(),
        // i.e. unrelated test cases can set the logger, and we can’t reliably test the success path.
        // (Therefore we also can't test logging end-to-end, by calling log::… and verifying the
        // C consumer receives the data.)
        // So, test just the failure path, by invoking the function twice.
        extern "C" fn noop_consumer(_: SequoiaLogLevel, _: *const c_char) {}
        let mut err_ptr: *mut SequoiaError = ptr::null_mut();
        _ = unsafe { super::sequoia_set_logger_consumer(noop_consumer, &mut err_ptr) };
        if !err_ptr.is_null() {
            unsafe { crate::sequoia_error_free(err_ptr) };
            err_ptr = ptr::null_mut();
        }
        let res = unsafe { super::sequoia_set_logger_consumer(noop_consumer, &mut err_ptr) };
        assert_ne!(res, 0);
        assert!(!err_ptr.is_null());
        unsafe { crate::sequoia_error_free(err_ptr) };
    }

    // with_fixture_sequoia_home_locked runs the provided function with a lock that serializes
    // accesses to the fixture Sequoia home.
    fn with_fixture_sequoia_home_locked<R>(f: impl FnOnce(std::path::PathBuf) -> R) -> R {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        let fixture_path_buf = Path::new(env!("CARGO_MANIFEST_DIR")).join("./src/data");
        let _guard = LOCK.lock().unwrap();
        return f(fixture_path_buf);
    }

    // with_c_mechanism_from_directory runs the provided function with a C-interface mechanism
    // in path, as a convenience for tests of other aspects of the C bindings.
    fn with_c_mechanism_from_directory<R>(
        path: impl AsRef<Path>,
        f: impl FnOnce(*mut SequoiaMechanism) -> R,
    ) -> R {
        let mut err_ptr: *mut SequoiaError = ptr::null_mut();

        let c_sequoia_home = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();
        let m = unsafe {
            super::sequoia_mechanism_new_from_directory(c_sequoia_home.as_ptr(), &mut err_ptr)
        };
        assert!(!m.is_null());
        assert!(err_ptr.is_null());

        let res = f(m);

        unsafe { sequoia_mechanism_free(m) };

        res
    }

    // with_c_fixture_mechanism runs the provided function with a C-interface mechanism
    // in fixture_path_buf(), as a convenience for tests of other aspects of the C bindings.
    fn with_c_fixture_mechanism<R>(f: impl FnOnce(*mut SequoiaMechanism) -> R) -> R {
        return with_fixture_sequoia_home_locked(|fixture_dir| {
            return with_c_mechanism_from_directory(fixture_dir, f);
        });
    }

    // with_c_ephemeral_mechanism runs the provided function with a C-interface ephemeral mechanism,
    // as a convenience for tests of other aspects of the C bindings.
    fn with_c_ephemeral_mechanism(f: impl FnOnce(*mut SequoiaMechanism)) {
        let mut err_ptr: *mut SequoiaError = ptr::null_mut();

        let m = unsafe { sequoia_mechanism_new_ephemeral(&mut err_ptr) };
        assert!(!m.is_null());
        assert!(err_ptr.is_null());

        f(m);

        unsafe { sequoia_mechanism_free(m) };
    }

    // import_private_key imports a certificate and the included private key into a mechanism.
    fn import_private_key(mech: &mut SequoiaMechanism, cert: &Cert) {
        let mut softkeys = None;
        for mut backend in mech
            .keystore
            .as_mut()
            .unwrap()
            .backends()
            .unwrap()
            .into_iter()
        {
            if backend.id().unwrap() == "softkeys" {
                softkeys = Some(backend);
                break;
            }
        }
        let mut softkeys = softkeys.unwrap();
        softkeys.import(&cert).unwrap();
        let cert = cert.clone().strip_secret_key_material();
        mech.certstore
            .update(Arc::new(sequoia_cert_store::LazyCert::from(cert)))
            .unwrap();
    }
}

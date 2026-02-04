# podman-sequoia

podman-sequoia provides a C shared library (`libpodman_sequoia.so`)
and [CGO](https://go.dev/wiki/cgo) stubs that enable to use
[sequoia-pgp] as a signing backend in container tools such as podman
or skopeo.

For building, you need rustc (version 1.79 or later), cargo, and
openssl-devel. For testing, you also need the `sq` command (version
1.3.0 or later).

## Building

To build the shared library and bindings on Linux, do:

```console
$ PREFIX=/usr LIBDIR="\${prefix}/lib64" cargo build --release
```

On macOS, prefix the command with one more value:
```console
$ DYLD_FALLBACK_LIBRARY_PATH="$(xcode-select --print-path)/Toolchains/XcodeDefault.xctoolchain/usr/lib/" PREFIX=…
```

## Installing

Just copy the shared library in the library search path:

```console
$ sudo cp -a rust/target/release/libpodman_sequoia.* /usr/lib64
```

## Testing

To test, in the top-level directory of containers image, do:
```console
$ LD_LIBRARY_PATH=$PWD/signature/internal/sequoia/rust/target/release \
  make BUILDTAGS=containers_image_sequoia
```

## License

Apache License 2.0

SPDX-License-Identifier: Apache-2.0

[sequoia-pgp]: https://sequoia-pgp.org/

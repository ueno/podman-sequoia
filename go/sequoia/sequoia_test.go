// SPDX-License-Identifier: LGPL-2.0-or-later

package sequoia_test

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ueno/podman-sequoia/go/sequoia"
	"io"
	"os/exec"
	"regexp"
	"testing"
)

func generateKey(dir string, email string) (string, error) {
	cmd := exec.Command("sq", "--home", dir, "key", "generate", "--userid", fmt.Sprintf("<%s>", email))
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	output, err := io.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return "", err
	}

	re := regexp.MustCompile("(?m)^ *Fingerprint: ([0-9A-F]+)")
	matches := re.FindSubmatch(output)
	if matches == nil {
		return "", errors.New("unable to extract fingerprint")
	}
	fingerprint := string(matches[1][:])
	cmd = exec.Command("sq", "--home", dir, "pki", "link", "add", "--ca", "*", fingerprint, "--all")
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return fingerprint, nil
}

func exportCert(dir string, email string) ([]byte, error) {
	cmd := exec.Command("sq", "--home", dir, "cert", "export", "--email", email)
	return cmd.Output()
}

func TestNewMechanismFromDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := sequoia.NewMechanismFromDirectory(dir)
	if err != nil {
		t.Errorf("unable to initialize a mechanism: %v", err)
	}
	_, err = generateKey(dir, "foo@example.org")
	if err != nil {
		t.Errorf("unable to generate key: %v", err)
	}
	_, err = sequoia.NewMechanismFromDirectory(dir)
	if err != nil {
		t.Errorf("unable to initialize a mechanism: %v", err)
	}
}

func TestNewEphemeralMechanism(t *testing.T) {
	dir := t.TempDir()
	fingerprint, err := generateKey(dir, "foo@example.org")
	if err != nil {
		t.Errorf("unable to generate key: %v", err)
	}
	output, err := exportCert(dir, "foo@example.org")
	_, keyIdentities, err := sequoia.NewEphemeralMechanism([][]byte{output})
	if err != nil {
		t.Errorf("unable to initialize a mechanism: %v", err)
	}
	if len(keyIdentities) != 1 || keyIdentities[0] != fingerprint {
		t.Errorf("keyIdentity differ from the original: %v != %v",
			keyIdentities[0], fingerprint)
	}
}

func TestSignVerify(t *testing.T) {
	dir := t.TempDir()
	fingerprint, err := generateKey(dir, "foo@example.org")
	if err != nil {
		t.Errorf("unable to generate key: %v", err)
	}
	m, err := sequoia.NewMechanismFromDirectory(dir)
	if err != nil {
		t.Errorf("unable to initialize a mechanism: %v", err)
	}
	input := []byte("Hello, world!")
	sig, err := m.Sign(input, fingerprint)
	if err != nil {
		t.Errorf("unable to sign: %v", err)
	}
	contents, keyIdentity, err := m.Verify(sig)
	if err != nil {
		t.Errorf("unable to verify: %v", err)
	}
	if !bytes.Equal(contents, input) {
		t.Errorf("contents differ from the original")
	}
	if keyIdentity != fingerprint {
		t.Errorf("keyIdentity differ from the original")
	}
}

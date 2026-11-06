//go:build native

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNewestRelease(t *testing.T) {
	releases := []githubRelease{
		{TagName: "v3-2026-11-06-162922"}, // timestamped master build
		{TagName: "v2.9.9"},
		{TagName: "v3.9.0"},
		{TagName: "v3.10.0"},
		{TagName: "v3.11.0", Draft: true},
		{TagName: "v3.12.0", Prerelease: true},
		{TagName: "v3.10.0-rc1"},
	}
	if got := newestRelease(releases); got != "v3.10.0" {
		t.Fatalf("newestRelease = %q, want v3.10.0", got)
	}
	if got := newestRelease(releases[:2]); got != "" {
		t.Fatalf("newestRelease without eligible tags = %q, want empty", got)
	}
}

func TestShouldInstall(t *testing.T) {
	cases := []struct {
		current, target string
		pinned, want    bool
	}{
		{"v3.1.0", "v3.1.1", false, true},
		{"v3.1.1", "v3.1.1", false, false},
		{"v3.2.0", "v3.1.9", false, false}, // never downgrade unprompted
		{"v3.2.0", "v3.1.9", true, true},   // explicit pin may downgrade
		{"v3.1.9", "v3.1.9", true, false},
		{"dev", "v3.0.0", false, true},
		{"v3-2026-11-06-162922", "v3.0.0", false, true},
	}
	for _, c := range cases {
		if got := shouldInstall(c.current, c.target, c.pinned); got != c.want {
			t.Errorf("shouldInstall(%q, %q, pinned=%v) = %v, want %v", c.current, c.target, c.pinned, got, c.want)
		}
	}
}

func signedManifest(t *testing.T, priv ed25519.PrivateKey, m releaseManifest) ([]byte, []byte) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data, ed25519.Sign(priv, data)
}

func TestVerifyManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := releaseManifest{Tag: "v3.1.0", Created: time.Now(), Assets: map[string]string{"etr-linux-amd64": "00"}}
	data, sig := signedManifest(t, priv, m)
	keys := []ed25519.PublicKey{otherPub, pub}

	if _, err := verifyManifest(data, sig, keys, "v3.1.0"); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if _, err := verifyManifest(data, sig, []ed25519.PublicKey{otherPub}, "v3.1.0"); err == nil {
		t.Fatal("manifest accepted with untrusted key")
	}
	tampered := []byte(strings.Replace(string(data), `"00"`, `"ff"`, 1))
	if _, err := verifyManifest(tampered, sig, keys, "v3.1.0"); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	// A genuine manifest for one tag must not authorize another tag.
	if _, err := verifyManifest(data, sig, keys, "v3.2.0"); err == nil {
		t.Fatal("manifest replayed onto another tag accepted")
	}
	if _, err := verifyManifest(data, sig[:10], keys, "v3.1.0"); err == nil {
		t.Fatal("truncated signature accepted")
	}
}

func TestParseReleaseKeys(t *testing.T) {
	if _, err := parseReleaseKeys(nil); err == nil {
		t.Fatal("empty key list accepted")
	}
	// The shipped key file must parse, even while it is still empty.
	if len(releaseSigningKeysPEM) > 0 {
		if _, err := parseReleaseKeys(releaseSigningKeysPEM); err != nil {
			t.Fatalf("release-signing.pub: %v", err)
		}
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	der2, _ := x509.MarshalPKIXPublicKey(pub2)
	p2 := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der2}))
	keys, err := parseReleaseKeys([]byte(p + "\n" + p2))
	if err != nil || len(keys) != 2 || !keys[0].Equal(pub) || !keys[1].Equal(pub2) {
		t.Fatalf("parseReleaseKeys = %v, %v", keys, err)
	}
	if _, err := parseReleaseKeys([]byte("not pem")); err == nil {
		t.Fatal("invalid PEM accepted")
	}
}

// CI signs with openssl; the updater verifies with crypto/ed25519.
func TestOpenSSLSignatureCompatibility(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	key, pubFile, msg, sigFile := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub"), filepath.Join(dir, "m"), filepath.Join(dir, "m.sig")
	os.WriteFile(msg, []byte(`{"tag":"v3.1.0"}`), 0600)
	for _, args := range [][]string{
		{"genpkey", "-algorithm", "ed25519", "-out", key},
		{"pkey", "-in", key, "-pubout", "-out", pubFile},
		{"pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", msg, "-out", sigFile},
	} {
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	pubPEM, _ := os.ReadFile(pubFile)
	keys, err := parseReleaseKeys(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(msg)
	sig, _ := os.ReadFile(sigFile)
	if !ed25519.Verify(keys[0], data, sig) {
		t.Fatal("openssl Ed25519 signature rejected by crypto/ed25519")
	}
}

// fakeBinary is a script standing in for a release binary's --version output.
func fakeBinary(tag string) []byte {
	return []byte("#!/bin/sh\necho " + tag + "\n")
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestInstallBinary(t *testing.T) {
	origSignal, origHealthy := signalDaemon, daemonHealthy
	defer func() { signalDaemon, daemonHealthy = origSignal, origHealthy }()
	signalDaemon = func(string) (int, error) { return 4242, nil }

	setup := func(t *testing.T) string {
		exe := filepath.Join(t.TempDir(), "etr-linux")
		if err := os.WriteFile(exe, fakeBinary("v3.0.0"), 0755); err != nil {
			t.Fatal(err)
		}
		return exe
	}
	installedTag := func(t *testing.T, exe string) string {
		out, err := exec.Command(exe, "--version").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}

	t.Run("success", func(t *testing.T) {
		daemonHealthy = func(int, string) bool { return true }
		exe := setup(t)
		bin := fakeBinary("v3.1.0")
		if err := installBinary(exe, bin, digest(bin), "v3.1.0"); err != nil {
			t.Fatal(err)
		}
		if got := installedTag(t, exe); got != "v3.1.0" {
			t.Fatalf("installed %q", got)
		}
		if got := installedTag(t, exe+".prev"); got != "v3.0.0" {
			t.Fatalf("previous binary is %q", got)
		}
	})

	t.Run("digest mismatch leaves binary untouched", func(t *testing.T) {
		exe := setup(t)
		bin := fakeBinary("v3.1.0")
		if err := installBinary(exe, bin, digest([]byte("other")), "v3.1.0"); err == nil {
			t.Fatal("mismatched digest accepted")
		}
		if got := installedTag(t, exe); got != "v3.0.0" {
			t.Fatalf("binary changed to %q", got)
		}
	})

	t.Run("wrong version leaves binary untouched", func(t *testing.T) {
		exe := setup(t)
		bin := fakeBinary("v3.0.5")
		if err := installBinary(exe, bin, digest(bin), "v3.1.0"); err == nil {
			t.Fatal("binary reporting the wrong version accepted")
		}
		if got := installedTag(t, exe); got != "v3.0.0" {
			t.Fatalf("binary changed to %q", got)
		}
	})

	t.Run("no running daemon is not an error", func(t *testing.T) {
		signalDaemon = func(string) (int, error) { return 0, nil }
		defer func() { signalDaemon = func(string) (int, error) { return 4242, nil } }()
		daemonHealthy = func(int, string) bool { t.Fatal("health checked without a daemon"); return false }
		exe := setup(t)
		bin := fakeBinary("v3.1.0")
		if err := installBinary(exe, bin, digest(bin), "v3.1.0"); err != nil {
			t.Fatal(err)
		}
		if got := installedTag(t, exe); got != "v3.1.0" {
			t.Fatalf("installed %q", got)
		}
	})

	t.Run("unhealthy daemon rolls back", func(t *testing.T) {
		daemonHealthy = func(int, string) bool { return false }
		exe := setup(t)
		bin := fakeBinary("v3.1.0")
		if err := installBinary(exe, bin, digest(bin), "v3.1.0"); err == nil {
			t.Fatal("failed restart not reported")
		}
		if got := installedTag(t, exe); got != "v3.0.0" {
			t.Fatalf("not rolled back, running %q", got)
		}
	})
}

func TestSignalRunningDaemonIgnoresStalePID(t *testing.T) {
	original := allowedConfDir
	allowedConfDir = t.TempDir()
	defer func() { allowedConfDir = original }()

	exe := filepath.Join(t.TempDir(), "etr-linux")
	if pid, err := signalRunningDaemon(exe); pid != 0 || err != nil {
		t.Fatalf("no pid file: got (%d, %v), want (0, nil)", pid, err)
	}
	// Our own pid runs the test binary, not exe, so it must not be signalled.
	if err := os.WriteFile(pidFile(), []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		t.Fatal(err)
	}
	if pid, err := signalRunningDaemon(exe); pid != 0 || err != nil {
		t.Fatalf("stale pid: got (%d, %v), want (0, nil)", pid, err)
	}
	if err := os.WriteFile(pidFile(), []byte("garbage"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := signalRunningDaemon(exe); err == nil {
		t.Fatal("invalid pid file accepted")
	}
}

//go:build native

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReloadNginxWaitsForApplyStatus(t *testing.T) {
	dir := t.TempDir()
	original := applyStatusPath
	applyStatusPath = filepath.Join(dir, "status.json")
	t.Cleanup(func() { applyStatusPath = original })

	config := &Config{ConfFilePath: filepath.Join(dir, "blocklist.conf")}
	if err := os.WriteFile(config.ConfFilePath, []byte("list"), 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("list"))
	report := func(s applyStatus) {
		s.SHA256 = hex.EncodeToString(sum[:])
		data, _ := json.Marshal(s)
		if err := os.WriteFile(applyStatusPath, data, 0644); err != nil {
			t.Fatal(err)
		}
	}

	report(applyStatus{OK: true, Time: time.Now().Add(time.Second)})
	if err := reloadNginx(config); err != nil {
		t.Fatalf("accepted blocklist reported as failure: %v", err)
	}

	report(applyStatus{OK: false, Error: "nginx -t failed", Time: time.Now().Add(time.Second)})
	if err := reloadNginx(config); err == nil || !strings.Contains(err.Error(), "nginx -t failed") {
		t.Fatalf("rejection not reported: %v", err)
	}

	if testing.Short() {
		return
	}
	// A result from before the file was written belongs to an earlier
	// identical blocklist and must not count.
	report(applyStatus{OK: true, Time: time.Now().Add(-time.Hour)})
	t.Setenv("ETR_APPLY_TIMEOUT", "5")
	if err := reloadNginx(config); err == nil || !strings.Contains(err.Error(), "did not report") {
		t.Fatalf("stale status accepted: %v", err)
	}
}

func TestPreflightRefusesRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := preflight(); err == nil {
		t.Fatal("native daemon allowed to run as root")
	}
}

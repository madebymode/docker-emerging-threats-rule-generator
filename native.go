//go:build native

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The native daemon runs as the unprivileged etr user and only writes its own
// state directory. etr-apply (root, cmd/etr-apply) validates each new
// blocklist there, installs it into nginx and reports the result.
//
// allowedConfDir can be overridden with NGINX_CONF_DIR (kept for tests and
// existing etr.env files); the systemd unit makes everything else read-only.
var allowedConfDir = "/var/lib/etr"

const defaultConfigPath = "/etc/etr/config.json"

// confPathHint explains the most likely cause of a rejected output path:
// a config.json from before the daemon/etr-apply split.
const confPathHint = "The native daemon writes only to /var/lib/etr; set nginx_conf_file_path to " +
	"/var/lib/etr/blocklist.conf and set the nginx include path in /etc/etr/apply.env (see native-install.md)."

// applyStatusPath is where etr-apply reports its result for each blocklist.
var applyStatusPath = "/var/lib/etr-apply/status.json"

// applyNudgeInterval is how long reloadNginx waits for a result before it
// touches the staged file to trigger etr-apply.path again.
var applyNudgeInterval = 10 * time.Second

// selfPath is resolved at startup: once self-update replaces the binary,
// /proc/self/exe points at the deleted old file.
var selfPath string

func init() {
	if dir := os.Getenv("NGINX_CONF_DIR"); dir != "" {
		allowedConfDir = dir
	}
	if p := os.Getenv("ETR_APPLY_STATUS"); p != "" {
		applyStatusPath = p
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			selfPath = resolved
		}
	}
}

// preflight refuses to run as root: nothing in the native daemon needs it,
// and the binary lives in a directory the etr user can write.
func preflight() error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("refusing to run as root. Run the daemon as the etr user (systemctl start etr), "+
			"or a one-off update with: sudo -u etr %s --force", selfPath)
	}
	return nil
}

// pidFile lets etr-update find the daemon without systemd or D-Bus access.
func pidFile() string {
	return filepath.Join(allowedConfDir, "etr.pid")
}

func daemonStarted() {
	if err := os.WriteFile(pidFile(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		logf("Warning: could not write %s, self-update will not restart the daemon: %v\n", pidFile(), err)
	}
}

// reexecSignals delivers SIGHUP, which etr-update sends after installing a
// new binary.
func reexecSignals() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}

// reexecSelf replaces the running daemon with the binary now at selfPath.
// The PID stays the same, so systemd sees no restart. It only returns if exec
// fails, in which case the old code keeps running.
func reexecSelf() {
	if selfPath == "" {
		logf("SIGHUP: cannot re-exec, executable path unknown\n")
		return
	}
	// The blocklist is already current; don't refetch every list on upgrade.
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "ETR_RUN_ON_START=")
	})
	env = append(env, "ETR_RUN_ON_START=false")
	logf("SIGHUP: re-executing %s\n", selfPath)
	err := syscall.Exec(selfPath, os.Args, env)
	logf("Re-exec failed, continuing on %s: %v\n", version, err)
}

// testNginxConfig is a no-op natively: the daemon cannot read nginx's TLS
// keys, so etr-apply runs `nginx -t` as root after validating the file.
func testNginxConfig(_ *Config) error {
	return nil
}

type applyStatus struct {
	SHA256 string    `json:"sha256"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error"`
	Time   time.Time `json:"time"`
}

// reloadNginx waits for etr-apply to report on the blocklist now on disk.
// etr-apply.path starts it whenever the file changes. A failure here makes
// applyBlocklist restore the previous file, which etr-apply then reinstalls.
func reloadNginx(config *Config) error {
	info, err := os.Stat(config.ConfFilePath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(config.ConfFilePath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])

	timeout := time.Duration(envInt("ETR_APPLY_TIMEOUT", 120, 5, 3600)) * time.Second
	deadline := time.Now().Add(timeout)
	// systemd reports etr-apply.path as started a few milliseconds before
	// its inotify watch is live, so the first blocklist after boot or install
	// can go unseen. Touching the file triggers it again; etr-apply is
	// idempotent.
	nudge := time.Now().Add(2 * time.Second)
	for {
		if s, ok := readApplyStatus(); ok && s.SHA256 == want && !s.Time.Before(info.ModTime()) {
			if !s.OK {
				return fmt.Errorf("etr-apply rejected the blocklist: %s", s.Error)
			}
			logf("etr-apply installed the blocklist (sha256 %s)\n", want[:12])
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("etr-apply did not report on the new blocklist within %s; "+
				"check `systemctl status etr-apply.path` and `journalctl -u etr-apply`", timeout)
		}
		if time.Now().After(nudge) {
			now := time.Now()
			if err := os.Chtimes(config.ConfFilePath, now, now); err != nil {
				logf("Warning: could not touch %s to retrigger etr-apply: %v\n", config.ConfFilePath, err)
			}
			nudge = now.Add(applyNudgeInterval)
		}
		time.Sleep(time.Second)
	}
}

func readApplyStatus() (applyStatus, bool) {
	var s applyStatus
	data, err := os.ReadFile(applyStatusPath)
	if err != nil {
		return s, false
	}
	return s, json.Unmarshal(data, &s) == nil
}

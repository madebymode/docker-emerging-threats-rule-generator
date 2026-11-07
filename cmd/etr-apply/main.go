// etr-apply installs the blocklist that the unprivileged ETR daemon stages in
// /var/lib/etr into nginx. It is the only part of a native install that runs
// as root, so it trusts nothing about the staged file: every line must match
// the generator's output grammar, or the file is rejected before nginx sees it.
//
// It is started by etr-apply.path whenever the staged file changes, and is
// never replaced by self-update. Settings come from the environment
// (etr-apply.service and /etc/etr/apply.env):
//
//	ETR_STAGED_FILE   staged blocklist    (default /var/lib/etr/blocklist.conf)
//	ETR_LIVE_FILE     nginx include path  (default /etc/nginx/conf.d/blocklist.conf)
//	ETR_STATUS_FILE   result for the daemon (default /var/lib/etr-apply/status.json)
//	NGINX_BIN         binary for `-t`     (default nginx)
//	NGINX_SERVICE     unit to reload      (default nginx)
//	ETR_APPLY_MAX_ENTRIES                 (default 2000000)
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"nginx_blacklist/internal/blocklistfmt"
)

// maxStagedSize bounds what is read from the unprivileged daemon's directory.
const maxStagedSize = 256 << 20

type status struct {
	SHA256 string    `json:"sha256"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	Time   time.Time `json:"time"`
}

func main() {
	log.SetFlags(0)
	start := time.Now()
	staged := env("ETR_STAGED_FILE", "/var/lib/etr/blocklist.conf")

	data, err := readStaged(staged)
	if errors.Is(err, fs.ErrNotExist) {
		log.Printf("%s does not exist; nothing to apply", staged)
		return
	}
	if err != nil {
		// Reading failed before we know what the daemon wrote, so there is no
		// hash to report against. The daemon times out and rolls back.
		log.Fatalf("reading %s: %v", staged, err)
	}
	sum := sha256.Sum256(data)
	result := status{SHA256: hex.EncodeToString(sum[:]), Time: start}

	if err := apply(data); err != nil {
		result.Error = err.Error()
		log.Printf("rejected blocklist %s: %v", result.SHA256[:12], err)
	} else {
		result.OK = true
	}
	if err := writeStatus(env("ETR_STATUS_FILE", "/var/lib/etr-apply/status.json"), result); err != nil {
		log.Fatalf("writing status: %v", err)
	}
	if !result.OK {
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// readStaged opens the file through an os.Root on its directory, so a
// symlink planted by the daemon cannot make root read a file outside it.
func readStaged(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// Nonblocking open prevents an attacker-owned FIFO from hanging root
	// before f.Stat can reject it. Regular files retain normal read behavior.
	f, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStagedSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStagedSize {
		return nil, fmt.Errorf("larger than %d bytes", maxStagedSize)
	}
	return data, nil
}

// apply validates data, installs it as the live include, and reloads nginx.
// Any failure after the live file changes restores the previous file.
func apply(data []byte) error {
	maxEntries, err := strconv.Atoi(env("ETR_APPLY_MAX_ENTRIES", "2000000"))
	if err != nil || maxEntries < 1 {
		return fmt.Errorf("invalid ETR_APPLY_MAX_ENTRIES")
	}
	entries, err := blocklistfmt.Validate(data, maxEntries)
	if err != nil {
		return err
	}

	live := env("ETR_LIVE_FILE", "/etc/nginx/conf.d/blocklist.conf")
	previous, err := os.ReadFile(live)
	hadPrevious := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reading %s: %v", live, err)
	}
	if hadPrevious && bytes.Equal(previous, data) {
		log.Printf("%s is already current (%d entries)", live, entries)
		return nil
	}

	if err := writeAtomic(live, data); err != nil {
		return fmt.Errorf("installing %s: %v", live, err)
	}
	nginxBin := env("NGINX_BIN", "nginx")
	service := env("NGINX_SERVICE", "nginx")

	if err := run(nginxBin, "-t"); err != nil {
		return restore(live, previous, hadPrevious, nginxBin, service, fmt.Errorf("%s -t rejected the blocklist: %v", nginxBin, err))
	}
	// reload-or-restart: a graceful reload where the unit has one, a
	// restart otherwise (ServerPilot documents only a restart for nginx-sp).
	if err := run("systemctl", "reload-or-restart", service); err != nil {
		return restore(live, previous, hadPrevious, nginxBin, service, fmt.Errorf("reloading %s: %v", service, err))
	}
	log.Printf("installed %d entries into %s and reloaded %s", entries, live, service)
	return nil
}

func restore(live string, previous []byte, hadPrevious bool, nginxBin, service string, cause error) error {
	var err error
	if hadPrevious {
		err = writeAtomic(live, previous)
	} else {
		err = os.Remove(live)
	}
	if err != nil {
		return fmt.Errorf("%v; restoring %s also failed, fix it by hand: %v", cause, live, err)
	}
	if hadPrevious && run(nginxBin, "-t") == nil {
		if err := run("systemctl", "reload-or-restart", service); err != nil {
			log.Printf("restored the previous blocklist, but reloading %s failed: %v", service, err)
		}
	}
	return fmt.Errorf("%v; previous blocklist restored", cause)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v\n%s", err, bytes.TrimSpace(out))
	}
	return nil
}

// writeAtomic replaces path with data via a temp file in the same directory.
// New files in nginx's config directory inherit its SELinux label.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".etr-apply-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writeStatus(path string, s status) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'))
}

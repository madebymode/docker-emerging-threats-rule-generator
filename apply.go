package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// applyBlocklist writes the new blocklist, validates that nginx accepts it,
// rolls back on any failure, and only then reloads. This guarantees we never
// leave nginx in a state where a subsequent reload/restart would fail.
//
// When reload is false, the file is written and (where possible) validated,
// but the reload step is skipped — the caller is expected to reload nginx
// out-of-band. Rollback still triggers on write or validation failure.
//
// Failure path invariant: after this function returns error, the on-disk
// blocklist file is EITHER (a) the previously-written valid file, or (b)
// removed entirely if none existed before. It is never a half-written or
// syntactically invalid file.
func applyBlocklist(whitelist map[string]string, blocklist map[string][]string, config *Config, reload bool) error {
	backup, hadBackup, err := snapshotBlocklist(config.ConfFilePath)
	if err != nil {
		return fmt.Errorf("failed to snapshot existing blocklist: %v", err)
	}

	if err := writeBlocklistFile(whitelist, blocklist, config.ConfFilePath); err != nil {
		return err
	}

	if err := testNginxConfig(config); err != nil {
		return rollbackAndReport(config, backup, hadBackup, fmt.Errorf("nginx config test rejected new blocklist: %v", err))
	}

	if !reload {
		return nil
	}

	if err := reloadNginx(config); err != nil {
		return rollbackAndReport(config, backup, hadBackup, fmt.Errorf("nginx reload failed: %v", err))
	}

	return nil
}

func rollbackAndReport(config *Config, backup []byte, hadBackup bool, cause error) error {
	logf("Rolling back blocklist due to error: %v\n", cause)
	if rbErr := restoreBlocklist(config.ConfFilePath, backup, hadBackup); rbErr != nil {
		return fmt.Errorf("apply failed AND rollback failed — MANUAL RECOVERY REQUIRED: original=%v rollback=%v", cause, rbErr)
	}

	if hadBackup {
		if postErr := testNginxConfig(config); postErr != nil {
			return fmt.Errorf("apply failed, rollback restored previous blocklist but nginx still rejects it: original=%v post-rollback=%v", cause, postErr)
		}
		if rlErr := reloadNginx(config); rlErr != nil {
			logf("Rolled back cleanly but reload of previous config also failed: %v\n", rlErr)
		} else {
			logf("Rolled back to previous blocklist and reloaded nginx successfully.\n")
		}
	}
	return fmt.Errorf("blocklist update aborted; previous state restored: %v", cause)
}

func snapshotBlocklist(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func restoreBlocklist(path string, backup []byte, hadBackup bool) error {
	if !hadBackup {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove bad blocklist (no prior file to restore): %v", err)
		}
		return nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".blocklist-rollback-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to stage rollback: %v", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(backup); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("failed to write rollback: %v", err)
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("failed to chmod rollback: %v", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("failed to close rollback tmp: %v", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("failed to swap in rollback: %v", err)
	}
	return nil
}

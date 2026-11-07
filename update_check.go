//go:build native

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

func checkForUpdates() error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("refusing to check releases as root; run etr-check-update.service")
	}
	keys, err := parseReleaseKeys(releaseSigningKeysPEM)
	if err != nil {
		return err
	}
	var notifiers []Notifier
	if os.Getenv("ETR_UPDATE_NOTIFY") == "true" {
		notifiers = loadNotifiers()
		if len(notifiers) == 0 {
			logf("ETR_UPDATE_NOTIFY=true but no notification channels are configured\n")
		}
	}
	reminder := time.Duration(envInt("ETR_UPDATE_REMINDER_HOURS", 168, 1, 8760)) * time.Hour
	return checkRelease(keys, notifiers, "/var/lib/etr", time.Now(), reminder)
}

// This path fetches only the release index, manifest and detached signature.
// It never calls installBinary, executes a download or signals the daemon.
func checkRelease(keys []ed25519.PublicKey, notifiers []Notifier, stateDir string, now time.Time, reminder time.Duration) error {
	body, err := downloadFile("https://api.github.com/repos/" + updateRepo + "/releases?per_page=50")
	if err != nil {
		return fmt.Errorf("listing releases: %v", err)
	}
	var releases []githubRelease
	if err := json.Unmarshal([]byte(body), &releases); err != nil {
		return fmt.Errorf("parsing release list: %v", err)
	}
	target := newestRelease(releases)
	if target == "" {
		logf("No eligible v3 release advertised; installed=%s\n", version)
		return nil
	}
	manifest, err := fetchReleaseManifest(target, keys)
	if err != nil {
		return fmt.Errorf("verifying %s: %v", target, err)
	}
	releaseURL := "https://github.com/" + updateRepo + "/releases/tag/" + target
	if !shouldInstall(version, target, false) {
		logf("No newer signed release: installed=%s available=%s published=%s %s\n", version, target, manifest.Created.Format(time.RFC3339), releaseURL)
		return nil
	}
	message := fmt.Sprintf("ETR software update available: installed=%s available=%s published=%s\n%s\nReview the release before installing. This check has not installed software.", version, target, manifest.Created.Format(time.RFC3339), releaseURL)
	logf("%s\n", message)
	if len(notifiers) == 0 {
		return nil // logging-only checks do not need writable state
	}

	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return fmt.Errorf("opening notification state: %v", err)
	}
	defer root.Close()
	notice, err := readReleaseNotice(root)
	if err != nil {
		return fmt.Errorf("reading notification state: %v", err)
	}
	if notice.Installed != version || notice.Available != target || notice.Sent == nil {
		notice = releaseNotice{Installed: version, Available: target, Sent: make(map[string]time.Time)}
	}
	subject := "[ETR] Software update available"
	if instance := os.Getenv("INSTANCE_NAME"); instance != "" {
		subject = "[ETR " + instance + "] Software update available"
	}
	var failures []error
	for _, notifier := range notifiers {
		last := notice.Sent[notifier.Name()]
		if !last.IsZero() && !now.Before(last) && now.Sub(last) < reminder {
			continue
		}
		if err := notifier.Send(subject, message); err != nil {
			failures = append(failures, fmt.Errorf("%s notification failed: %v", notifier.Name(), err))
			continue
		}
		notice.Sent[notifier.Name()] = now
		// Persist each success so a later channel failure does not resend it.
		if err := writeReleaseNotice(root, notice); err != nil {
			return fmt.Errorf("saving notification state: %v", err)
		}
		logf("Release notification sent via %s\n", notifier.Name())
	}
	return errors.Join(failures...)
}

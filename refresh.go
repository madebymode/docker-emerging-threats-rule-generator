package main

import (
	"fmt"
)

// runUpdate performs one full download → generate → apply cycle. Returns nil on
// success; on failure logs and notifies, and (in daemon mode) leaves the daemon
// running so the next scheduled window can retry.
func runUpdate(config *Config, notifiers []Notifier, subjectPrefix string) error {
	failureThreshold := envInt("BLOCKLIST_FAILURE_THRESHOLD", 30, 0, 100)

	whitelist := make(map[string]string)
	for _, address := range config.LocalWhitelist {
		whitelist[address] = "local_whitelist"
	}
	for _, url := range config.RemoteWhitelists {
		content, err := downloadFile(url)
		if err != nil {
			logf("Failed to download file from %s: %v\n", redactURL(url), err)
			continue
		}
		addresses := parseIPAddresses(content)
		logf("Whitelist source %s: %d entries\n", redactURL(url), len(addresses))
		for address := range addresses {
			whitelist[address] = url
		}
	}

	blocklist := make(map[string][]string)
	for _, address := range config.LocalBlocklist {
		blocklist[address] = append(blocklist[address], "local_blocklist")
	}

	remoteBlocklistFailures := 0
	for _, url := range config.RemoteBlocklists {
		content, err := downloadFile(url)
		if err != nil {
			logf("Failed to download file from %s: %v\n", redactURL(url), err)
			remoteBlocklistFailures++
			continue
		}
		addresses := parseIPAddresses(content)
		logf("Blocklist source %s: %d entries\n", redactURL(url), len(addresses))
		for address := range addresses {
			blocklist[address] = append(blocklist[address], url)
		}
	}
	logf("Collected %d unique whitelist and %d unique blocklist entries (%d/%d remote blocklists fetched)\n",
		len(whitelist), len(blocklist),
		len(config.RemoteBlocklists)-remoteBlocklistFailures, len(config.RemoteBlocklists))

	if len(config.RemoteBlocklists) > 0 {
		failurePct := remoteBlocklistFailures * 100 / len(config.RemoteBlocklists)
		if failurePct >= failureThreshold {
			msg := fmt.Sprintf(
				"%d/%d remote blocklist source(s) failed (%d%% >= threshold %d%%); preserving existing blocklist.",
				remoteBlocklistFailures, len(config.RemoteBlocklists), failurePct, failureThreshold,
			)
			logf("%s\n", msg)
			notify(notifiers, subjectPrefix+"Blocklist update abandoned", msg)
			return fmt.Errorf("%s", msg)
		}
	}

	reload := shouldReloadNginx()
	if err := applyBlocklist(whitelist, blocklist, config, reload); err != nil {
		logf("%v\n", err)
		notify(notifiers, subjectPrefix+"Blocklist apply failed", err.Error())
		return err
	}

	logBlocklistSuccess(config, reload)
	return nil
}

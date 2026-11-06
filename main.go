package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func logf(format string, args ...interface{}) {
	fmt.Printf("["+time.Now().Format("2006/01/02 15:04:05")+"] "+format, args...)
}

// version is the release tag, set at build time with -ldflags "-X main.version=v3.1.0".
var version = "dev"

func main() {
	force := flag.Bool("force", false, "Run one update immediately and exit, regardless of ETR_DAEMON")
	showVersion := flag.Bool("version", false, "Print the version and exit")
	update := flag.Bool("self-update", false, "Install the newest signed v3 release and exit (native build only)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *update {
		if err := selfUpdate(); err != nil {
			logf("Self-update failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := preflight(); err != nil {
		logf("ERROR: %v\n", err)
		os.Exit(1)
	}

	config, err := readConfig(defaultConfigPath)
	if err != nil {
		logf("Failed to read config file: %v\n", err)
		os.Exit(1)
	}

	notifiers := loadNotifiers()
	instanceName := os.Getenv("INSTANCE_NAME")
	subjectPrefix := "[ETR] "
	if instanceName != "" {
		subjectPrefix = "[ETR " + instanceName + "] "
	}

	// Validate the output path before touching the network — fail fast.
	if err := validateConfFilePath(config.ConfFilePath); err != nil {
		logf("Invalid nginx_conf_file_path in config: %v\n%s\n", err, confPathHint)
		os.Exit(1)
	}

	// --force is the operator escape hatch: trigger an immediate update from the
	// CLI even when a daemon is already scheduling runs on its own timer.
	if *force || os.Getenv("ETR_DAEMON") != "true" {
		if err := runUpdate(config, notifiers, subjectPrefix); err != nil {
			os.Exit(1)
		}
		return
	}

	logf("Daemon mode: self-scheduling updates in-process\n")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	reexec := reexecSignals()
	daemonStarted()

	// Fresh install should get a blocklist immediately; users deploying at peak
	// hours can set ETR_RUN_ON_START=false to defer the first run to the window.
	// However, if the on-disk file doesn't exist yet, we ALWAYS build it now —
	// otherwise nginx would either reload a missing include or serve traffic
	// with no blocklist until the first window.
	_, statErr := os.Stat(config.ConfFilePath)
	blocklistMissing := os.IsNotExist(statErr)
	switch {
	case blocklistMissing:
		logf("Blocklist file %s does not exist; building initial list before scheduling\n", config.ConfFilePath)
		_ = runUpdate(config, notifiers, subjectPrefix)
	case os.Getenv("ETR_RUN_ON_START") != "false":
		_ = runUpdate(config, notifiers, subjectPrefix)
	default:
		logf("ETR_RUN_ON_START=false: deferring initial update to first scheduled window\n")
	}

	for {
		next := computeNextRun()
		logf("Next scheduled update at %s (in %s)\n",
			next.Format("2006-01-02 15:04:05 MST"),
			time.Until(next).Round(time.Second))

		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			logf("Received shutdown signal, exiting daemon\n")
			return
		case <-reexec:
			// Self-update installed a new binary. A SIGHUP that arrives
			// during an update waits here until that update finishes.
			timer.Stop()
			reexecSelf()
			continue
		case <-timer.C:
		}

		_ = runUpdate(config, notifiers, subjectPrefix)
	}
}

// computeNextRun returns the next scheduled update time in local time.
// Default: 03:00 local with up to 60 minutes of jitter to spread load across
// deployments that pull from the same upstream blocklist sources.
func computeNextRun() time.Time {
	hour := envInt("ETR_AT_HOUR", 3, 0, 23)
	jitterMax := envInt("ETR_JITTER_MINUTES", 60, 0, 240)

	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	if jitterMax > 0 {
		next = next.Add(time.Duration(rand.IntN(jitterMax*60)) * time.Second)
	}
	return next
}

func envInt(key string, def, min, max int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		logf("Invalid %s=%q (must be int in [%d,%d]), using default %d\n", key, v, min, max, def)
		return def
	}
	return n
}

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
			logf("Failed to download file from %s: %v\n", url, err)
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
			logf("Failed to download file from %s: %v\n", url, err)
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

	reload := os.Getenv("RESTART_CONTAINERS") != "false"
	if err := applyBlocklist(whitelist, blocklist, config, reload); err != nil {
		logf("%v\n", err)
		notify(notifiers, subjectPrefix+"Blocklist apply failed", err.Error())
		return err
	}

	if reload {
		logf("Blocklist applied and nginx reloaded successfully.\n")
	} else {
		logf("Blocklist applied (RESTART_CONTAINERS=false: reload skipped, handle externally).\n")
	}
	return nil
}

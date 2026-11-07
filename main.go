package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
	check := flag.Bool("check-update", false, "Check signed releases without installing software (native build only)")
	flag.Parse()
	if *check && *update {
		logf("--check-update and --self-update cannot be combined\n")
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *check {
		if err := checkForUpdates(); err != nil {
			logf("Release check failed: %v\n", err)
			os.Exit(1)
		}
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

package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/docker/docker/client"
)

func logf(format string, args ...interface{}) {
	fmt.Printf("["+time.Now().Format("2006/01/02 15:04:05")+"] "+format, args...)
}

// allowedConfDir is the only directory the blocklist file may be written into.
// Declared as a var so tests can override it to a temp directory.
var allowedConfDir = "/app/nginx/conf"

// main is the entry point for the application
func main() {
	config, err := readConfig("/app/config.json")
	if err != nil {
		logf("Failed to read config file: %v\n", err)
		return
	}

	notifiers := loadNotifiers()

	instanceName := os.Getenv("INSTANCE_NAME")
	subjectPrefix := "[ETR] "
	if instanceName != "" {
		subjectPrefix = "[ETR " + instanceName + "] "
	}

	failureThreshold := 30
	if v := os.Getenv("BLOCKLIST_FAILURE_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			failureThreshold = n
		} else {
			logf("Invalid BLOCKLIST_FAILURE_THRESHOLD %q, using default 30\n", v)
		}
	}

	// Validate the output path before touching the network — fail fast.
	if err := validateConfFilePath(config.ConfFilePath); err != nil {
		logf("Invalid nginx_conf_file_path in config: %v\n", err)
		return
	}

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
		for address := range addresses {
			blocklist[address] = append(blocklist[address], url)
		}
	}

	if len(config.RemoteBlocklists) > 0 {
		failurePct := remoteBlocklistFailures * 100 / len(config.RemoteBlocklists)
		if failurePct >= failureThreshold {
			msg := fmt.Sprintf(
				"%d/%d remote blocklist source(s) failed (%d%% >= threshold %d%%); preserving existing blocklist.",
				remoteBlocklistFailures, len(config.RemoteBlocklists), failurePct, failureThreshold,
			)
			logf("%s\n", msg)
			notify(notifiers, subjectPrefix+"Blocklist update abandoned", msg)
			return
		}
	}

	err = writeBlocklistFile(whitelist, blocklist, config.ConfFilePath)
	if err != nil {
		logf("Failed to write blocklist file: %v\n", err)
		return
	}

	if os.Getenv("RESTART_CONTAINERS") == "false" {
		logf("RESTART_CONTAINERS=false: skipping container restart. Reload nginx via external cron or orchestrator.\n")
		logf("Blocklist.conf file created successfully.\n")
		return
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logf("Failed to create Docker client: %v\n", err)
		return
	}

	if err := restartNginxContainers(cli, config.NginxContainerNames); err != nil {
		msg := fmt.Sprintf("Failed to restart nginx containers: %v", err)
		logf("%s\n", msg)
		notify(notifiers, subjectPrefix+"Nginx restart failed", msg)
		return
	}

	logf("Blocklist.conf file created and Nginx containers restarted successfully.\n")
}

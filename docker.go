//go:build !native

package main

import (
	"context"
	"fmt"
	"os"

	// The image is FROM scratch with no /usr/share/zoneinfo; embed the zone
	// database so TZ=<zone> overrides resolve without OS packages.
	_ "time/tzdata"

	"github.com/moby/moby/client"
)

var allowedConfDir = "/app/nginx/conf"

const defaultConfigPath = "/app/config.json"

// preflight refuses to start in a misconfigured container. The image has no
// shell, so these checks live here rather than in an entrypoint script.
func preflight() error {
	logf("Starting as uid %d (gid %d)\n", os.Geteuid(), os.Getegid())
	return checkRuntime(os.Geteuid(), allowedConfDir)
}

func shouldReloadNginx() bool {
	return os.Getenv("RESTART_CONTAINERS") != "false"
}

func logBlocklistSuccess(_ *Config, reload bool) {
	if reload {
		logf("Blocklist applied and nginx reloaded successfully.\n")
	} else {
		logf("Blocklist applied (RESTART_CONTAINERS=false: reload skipped, handle externally).\n")
	}
}

// selfUpdate is native-only: containers are updated by pulling a new image.
func selfUpdate() error {
	return fmt.Errorf("self-update is not available in the Docker image; pull a new image instead")
}

const confPathHint = "Mount the shared nginx volume at /app/nginx/conf and write the blocklist inside it."

func checkForUpdates() error {
	return fmt.Errorf("release checking is native-only; manage Docker image updates through your deployment tooling")
}

// The daemon hooks below support native self-update and do nothing here.
func daemonStarted() {}

func reexecSignals() <-chan os.Signal { return nil }

func reexecSelf() {}

func checkRuntime(euid int, confDir string) error {
	if euid == 0 {
		return fmt.Errorf("container is running as root. This image is designed to run as uid 1000 (etr-updater). " +
			"Remove any 'user: root' override or --user=0 flag")
	}
	f, err := os.CreateTemp(confDir, ".etr-write-check-*")
	if err != nil {
		return fmt.Errorf("%s is not writable by uid %d. "+
			"Named volumes inherit ownership from the image on first run — check that the volume is fresh. "+
			"For bind mounts, run: sudo chown -R 1000:987 <host-path>", confDir, euid)
	}
	f.Close()
	os.Remove(f.Name())
	return nil
}

// testNginxConfig is a no-op for the Docker variant. The nginx binary lives
// inside a separate container, so we can't shell out to `nginx -t` locally.
// Safety here is bounded by applyBlocklist's rollback path: if the container
// restart fails because of a bad config, the previous blocklist is restored
// and the restart is retried.
func testNginxConfig(_ *Config) error {
	return nil
}

// reloadNginx creates a Docker client and restarts the configured nginx containers.
// If a container fails to come back up (e.g. because of a bad config file we just
// wrote), the caller in applyBlocklist rolls back and retries.
func reloadNginx(config *Config) error {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %v", err)
	}
	defer cli.Close()
	return restartNginxContainers(cli, config.NginxContainerNames)
}

// restartNginxContainers restarts specified Docker containers.
// Container names are validated before use and each Docker API call has a hard timeout.
// ContainerRestart is used as a single atomic call so the container is never left stopped
// if the start phase fails.
func restartNginxContainers(cli *client.Client, containerNames []string) error {
	for _, containerName := range containerNames {
		if err := validateContainerName(containerName); err != nil {
			return fmt.Errorf("invalid container name: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), dockerOpTimeout)
		_, err := cli.ContainerRestart(ctx, containerName, client.ContainerRestartOptions{})
		cancel()
		if err != nil {
			return fmt.Errorf("failed to restart container %s: %v", containerName, err)
		}

		logf("Container %s restarted successfully.\n", containerName)
	}

	return nil
}

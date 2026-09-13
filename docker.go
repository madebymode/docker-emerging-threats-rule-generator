//go:build !native

package main

import (
	"context"
	"fmt"

	"github.com/moby/moby/client"
)

var allowedConfDir = "/app/nginx/conf"

const defaultConfigPath = "/app/config.json"

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
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
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

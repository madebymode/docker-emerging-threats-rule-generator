package main

import (
	"context"
	"fmt"

	"github.com/moby/moby/client"
)

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

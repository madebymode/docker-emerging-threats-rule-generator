package main

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// restartNginxContainers restarts specified Docker containers.
// Container names are validated before use and each Docker API call has a hard timeout.
func restartNginxContainers(cli *client.Client, containerNames []string) error {
	for _, containerName := range containerNames {
		if err := validateContainerName(containerName); err != nil {
			return fmt.Errorf("invalid container name: %v", err)
		}

		stopCtx, stopCancel := context.WithTimeout(context.Background(), dockerOpTimeout)
		stopErr := cli.ContainerStop(stopCtx, containerName, container.StopOptions{})
		stopCancel()
		if stopErr != nil {
			return fmt.Errorf("failed to stop container %s: %v", containerName, stopErr)
		}

		startCtx, startCancel := context.WithTimeout(context.Background(), dockerOpTimeout)
		startErr := cli.ContainerStart(startCtx, containerName, container.StartOptions{})
		startCancel()
		if startErr != nil {
			return fmt.Errorf("failed to start container %s: %v", containerName, startErr)
		}

		logf("Container %s restarted successfully.\n", containerName)
	}

	return nil
}

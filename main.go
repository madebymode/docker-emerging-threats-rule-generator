package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types/container"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	"github.com/docker/docker/client"
	"golang.org/x/net/context"
)

// Config represents the structure of the configuration file
type Config struct {
	BlockLists          []string `json:"block_lists"`
	ConfFilePath        string   `json:"nginx_conf_file_path"`
	NginxContainerNames []string `json:"nginx_container_names"`
}

func readConfig(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := &Config{}
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func downloadFile(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error fetching URL %s: status code %d", url, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func parseIPAddresses(contents string) map[string]struct{} {
	re := regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)
	matches := re.FindAllString(contents, -1)

	addresses := make(map[string]struct{})
	for _, match := range matches {
		addresses[match] = struct{}{}
	}

	return addresses
}

func writeBlocklistFile(addresses map[string]struct{}, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString("# blocklist.conf\n\ngeo $blocked_ip {\n    default        0;\n\n")
	if err != nil {
		return err
	}

	for address := range addresses {
		_, err = writer.WriteString(fmt.Sprintf("    %s    1;\n", address))
		if err != nil {
			return err
		}
	}

	_, err = writer.WriteString("\n}")
	if err != nil {
		return err
	}

	return writer.Flush()
}

func restartNginxContainers(cli *client.Client, containerNames []string) error {
	ctx := context.Background()

	for _, containerName := range containerNames {

		// Stop the container
		if err := cli.ContainerStop(ctx, containerName, container.StopOptions{}); err != nil {
			return fmt.Errorf("failed to stop container %s: %v", containerName, err)
		}

		// Start the container again
		if err := cli.ContainerStart(ctx, containerName, container.StartOptions{}); err != nil {
			return fmt.Errorf("failed to start container %s: %v", containerName, err)
		}

		fmt.Printf("Container %s restarted successfully.\n", containerName)
	}

	return nil
}

func main() {
	config, err := readConfig("config.json")
	if err != nil {
		fmt.Printf("Failed to read config file: %v\n", err)
		return
	}

	allAddresses := make(map[string]struct{})

	for _, url := range config.BlockLists {
		content, err := downloadFile(url)
		if err != nil {
			fmt.Printf("Failed to download file from %s: %v\n", url, err)
			continue
		}

		addresses := parseIPAddresses(content)
		for address := range addresses {
			allAddresses[address] = struct{}{}
		}
	}

	err = writeBlocklistFile(allAddresses, config.ConfFilePath)
	if err != nil {
		fmt.Printf("Failed to write blocklist file: %v\n", err)
		return
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		fmt.Printf("Failed to create Docker client: %v\n", err)
		return
	}

	// Use the container names from the config to restart Nginx containers
	if err := restartNginxContainers(cli, config.NginxContainerNames); err != nil {
		fmt.Printf("Failed to restart Nginx containers: %v\n", err)
		return
	}

	fmt.Println("Blocklist.conf file created and Nginx containers restarted successfully.")
}

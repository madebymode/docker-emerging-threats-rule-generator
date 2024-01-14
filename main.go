package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
)

// Config represents the structure of the configuration file
type Config struct {
	BlockLists   []string `json:"block_lists"`
	ConfFilePath string   `json:"nginx_conf_file_path"`
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

	fmt.Println("blocklist.conf file created successfully.")
}

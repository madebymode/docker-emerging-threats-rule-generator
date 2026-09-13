//go:build native

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// allowedConfDir is the directory the blocklist file may be written into.
// Override at runtime with the NGINX_CONF_DIR environment variable.
var allowedConfDir = "/etc/nginx"

const defaultConfigPath = "/etc/etr/config.json"

func init() {
	if dir := os.Getenv("NGINX_CONF_DIR"); dir != "" {
		allowedConfDir = dir
	}
}

// nginxService resolves the systemd unit name.
// Precedence: NGINX_SERVICE env > config nginx_service_name > "nginx".
func nginxService(config *Config) string {
	if s := os.Getenv("NGINX_SERVICE"); s != "" {
		return s
	}
	if config.NginxServiceName != "" {
		return config.NginxServiceName
	}
	return "nginx"
}

// nginxBinary resolves the nginx binary used for `nginx -t` validation.
// Precedence: NGINX_BIN env > service name (they match on nginx and nginx-sp).
func nginxBinary(config *Config) string {
	if b := os.Getenv("NGINX_BIN"); b != "" {
		return b
	}
	return nginxService(config)
}

// testNginxConfig runs `nginx -t` to validate the full nginx configuration,
// including whatever we just wrote. Returns error if the config is invalid —
// the caller must then roll back to keep nginx safely reloadable.
func testNginxConfig(config *Config) error {
	bin := nginxBinary(config)
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("nginx binary %q not found in PATH; set NGINX_BIN or install nginx", bin)
	}
	out, err := exec.Command(bin, "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s -t rejected config: %v\n%s", bin, err, out)
	}
	return nil
}

// reloadNginx sends SIGHUP via systemd for a graceful reload — existing
// connections are drained, new workers pick up the new config. No dropped requests.
func reloadNginx(config *Config) error {
	svc := nginxService(config)
	out, err := exec.Command("systemctl", "reload", svc).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl reload %s failed: %v\n%s", svc, err, out)
	}
	logf("systemctl reload %s: OK\n", svc)
	return nil
}

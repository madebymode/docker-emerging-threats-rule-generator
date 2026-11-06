//go:build !native

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

func TestCheckRuntime(t *testing.T) {
	dir := t.TempDir()
	if err := checkRuntime(1000, dir); err != nil {
		t.Fatalf("writable dir rejected: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("write check left files behind: %v", entries)
	}
	if err := checkRuntime(0, dir); err == nil || !strings.Contains(err.Error(), "running as root") {
		t.Fatalf("root not rejected: %v", err)
	}
	if err := checkRuntime(1000, filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("unwritable dir not rejected: %v", err)
	}
}

func TestRestartUsesDockerAPI(t *testing.T) {
	var restarted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/restart") {
			restarted = append(restarted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	cli, err := client.New(client.WithHost(server.URL), client.WithAPIVersion("1.56"))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := restartNginxContainers(cli, []string{"nginx-checker"}); err != nil {
		t.Fatal(err)
	}
	if len(restarted) != 1 || restarted[0] != "/v1.56/containers/nginx-checker/restart" {
		t.Fatalf("unexpected restarts: %v", restarted)
	}
	if err := restartNginxContainers(cli, []string{"../other"}); err == nil {
		t.Fatal("invalid name accepted")
	}
	if len(restarted) != 1 {
		t.Fatal("invalid name reached Docker API")
	}
}

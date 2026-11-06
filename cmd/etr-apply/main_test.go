package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const goodList = "# blocklist.conf\n\ngeo $blocked_source {\n    default        \"\";\n\n    1.2.3.4    local;\n\n}"

type fixture struct {
	dir, staged, live, statusFile, calls string
}

// newFixture points etr-apply at a temp tree and puts fake nginx and
// systemctl commands first in PATH. They log their arguments, and fail when
// a file named fail-<command> exists in the fixture directory.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses shell scripts")
	}
	dir := t.TempDir()
	f := &fixture{
		dir:        dir,
		staged:     filepath.Join(dir, "etr", "blocklist.conf"),
		live:       filepath.Join(dir, "nginx", "blocklist.conf"),
		statusFile: filepath.Join(dir, "status.json"),
		calls:      filepath.Join(dir, "calls"),
	}
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, filepath.Dir(f.staged), filepath.Dir(f.live)} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"nginx", "systemctl"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> '" + f.calls + "'\n" +
			"[ ! -e '" + filepath.Join(dir, "fail-"+name) + "' ]\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ETR_STAGED_FILE", f.staged)
	t.Setenv("ETR_LIVE_FILE", f.live)
	t.Setenv("ETR_STATUS_FILE", f.statusFile)
	return f
}

func (f *fixture) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f *fixture) fail(t *testing.T, command string) {
	f.write(t, filepath.Join(f.dir, "fail-"+command), "")
}

func TestApplyInstallsAndReloads(t *testing.T) {
	f := newFixture(t)
	if err := apply([]byte(goodList)); err != nil {
		t.Fatal(err)
	}
	if got := f.read(t, f.live); got != goodList {
		t.Fatalf("live file = %q", got)
	}
	if got := f.read(t, f.calls); got != "nginx -t\nsystemctl reload-or-restart nginx\n" {
		t.Fatalf("calls = %q", got)
	}
	info, err := os.Stat(f.live)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("live file mode %v", info.Mode().Perm())
	}
}

func TestApplyUnchangedSkipsReload(t *testing.T) {
	f := newFixture(t)
	f.write(t, f.live, goodList)
	if err := apply([]byte(goodList)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.calls); !os.IsNotExist(err) {
		t.Fatal("nginx was touched for an unchanged blocklist")
	}
}

func TestApplyRejectsBeforeTouchingNginx(t *testing.T) {
	f := newFixture(t)
	f.write(t, f.live, goodList)
	if err := apply([]byte(strings.Replace(goodList, "1.2.3.4    local;", "include /etc/shadow;", 1))); err == nil {
		t.Fatal("hostile blocklist accepted")
	}
	if got := f.read(t, f.live); got != goodList {
		t.Fatal("live file changed")
	}
	if _, err := os.Stat(f.calls); !os.IsNotExist(err) {
		t.Fatal("nginx was run on a rejected blocklist")
	}
}

func TestApplyRestoresWhenNginxRejects(t *testing.T) {
	f := newFixture(t)
	previous := strings.Replace(goodList, "1.2.3.4", "5.6.7.8", 1)
	f.write(t, f.live, previous)
	f.fail(t, "nginx")
	if err := apply([]byte(goodList)); err == nil {
		t.Fatal("nginx -t failure not reported")
	}
	if got := f.read(t, f.live); got != previous {
		t.Fatalf("previous blocklist not restored: %q", got)
	}
}

func TestApplyRestoresWhenReloadFails(t *testing.T) {
	f := newFixture(t)
	f.fail(t, "systemctl")
	if err := apply([]byte(goodList)); err == nil {
		t.Fatal("reload failure not reported")
	}
	if _, err := os.Stat(f.live); !os.IsNotExist(err) {
		t.Fatal("new blocklist left in place with no previous file to restore")
	}
}

func TestReadStagedRefusesSymlinkOutOfDirectory(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.dir, "secret")
	f.write(t, secret, "root only")
	if err := os.Symlink(secret, f.staged); err != nil {
		t.Fatal(err)
	}
	if _, err := readStaged(f.staged); err == nil {
		t.Fatal("followed a symlink out of the staging directory")
	}
}

func TestReadStagedRefusesNonRegularFile(t *testing.T) {
	f := newFixture(t)
	if err := os.Mkdir(f.staged, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := readStaged(f.staged); err == nil {
		t.Fatal("accepted a directory")
	}
}

// TestMainReportsResult runs the built command, as etr-apply.service does,
// and checks the status file the daemon waits for.
func TestMainReportsResult(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(f.dir, "etr-apply")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	f.write(t, f.staged, goodList)
	if out, err := exec.Command(exe).CombinedOutput(); err != nil {
		t.Fatalf("etr-apply failed: %v\n%s", err, out)
	}
	var s status
	if err := json.Unmarshal([]byte(f.read(t, f.statusFile)), &s); err != nil {
		t.Fatal(err)
	}
	if !s.OK || len(s.SHA256) != 64 || s.Time.IsZero() {
		t.Fatalf("status = %+v", s)
	}

	f.write(t, f.staged, goodList+"\nlog_format x;")
	if err := exec.Command(exe).Run(); err == nil {
		t.Fatal("exit status 0 for a rejected blocklist")
	}
	if err := json.Unmarshal([]byte(f.read(t, f.statusFile)), &s); err != nil {
		t.Fatal(err)
	}
	if s.OK || s.Error == "" {
		t.Fatalf("status = %+v", s)
	}

	if err := os.Remove(f.staged); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(exe).CombinedOutput(); err != nil {
		t.Fatalf("missing staged file should be a no-op: %v\n%s", err, out)
	}
}

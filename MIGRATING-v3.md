# Migrating to ETR v3

ETR v3 keeps daily updates, IPv4/IPv6 lists, whitelist exclusions, source labels,
Docker container restarts, and Telegram/SMTP/webhook notifications. Configuration
keys and environment variable names are unchanged. The major version makes the
stricter security behavior explicit for existing deployments.

## Deployment changes

- Change `mxmd/etr:v2` to `mxmd/etr:v3` after the v3 image is published. The release
  workflow publishes v3 aliases and versioned tags; it does not update the v2 alias.
- Copy the generator's `security_opt`, `cap_drop`, `cap_add`, and `pids_limit`
  settings from `docker-compose.example.yml`. Root cron and startup need only
  `CHOWN`, `DAC_OVERRIDE`, `SETUID`, and `SETGID`; the updater still runs as `anubis`
  by default. `RUN_AS_ROOT=true` remains supported.
- Keep the generator's rules volume writable. Mount the rules volume and
  `default.conf` read-only in nginx. Edit nginx configuration on the host instead
  of from inside nginx. Generated rules are readable across different nginx UIDs.
- `/app`, its executable files, and the cron spool are now root-owned. Custom
  commands running as `anubis` must write to `/app/nginx/conf` or `/tmp`, rather
  than modifying application files. Custom cron schedules require a root-owned
  replacement spool with a root-owned `root` file (mode `0600`).
- `DOCKER_HOST_GID` must be numeric. Existing groups with that GID are reused.
  Startup stops on permission or group setup failures instead of continuing with
  an incorrectly configured runtime.
- Docker socket access requires an explicit bind mount. The image no longer
  declares an anonymous volume at `/var/run/docker.sock`.

## Nginx now runs without root

All examples use `nginxinc/nginx-unprivileged:alpine-slim`, with all capabilities
removed, no-new-privileges, a read-only root filesystem, and writable temporary
storage in `/tmp`. The upstream image listens on port 8080 and keeps its PID and
temporary files in `/tmp`; see the [upstream image documentation](https://github.com/nginx/docker-nginx-unprivileged).

Update internal checker URLs to `http://etr-blocker-nginx:8080/check_ip` (or your
service name), Caddy's forward-auth upstream to port 8080, and container-side
published ports from 80 to 8080. The provided reverse-proxy example retains host
port 80 (`80:8080`), and pfSense retains host port 8080 (`127.0.0.1:8080:8080`).
Replace the mounted `default.conf` with the v3 version, which listens on 8080.
Existing configurations listening on 80 need the same edit.

The slim variant retains the modules used by this app and omits optional image/XSLT/JavaScript modules and curl. Use built-in `wget` for in-container diagnostics; deployments using custom optional nginx modules can select the full `alpine` variant.

Standard logs still go to Docker stdout. If you have customized nginx to also
write file logs, give its UID write permission on that log volume before upgrading.
Rules remain writable only in the generator and read-only in nginx.

## Input handling changes

- Redirects for remote IP lists must satisfy the same HTTPS and public-address
  checks as the original URL. Multicast and unspecified addresses are rejected.
- Downloads larger than 50 MiB fail instead of silently accepting a truncated
  list. Failed blocklist downloads count toward the existing failure threshold.
- Output files must be below `/app/nginx/conf`; symlinks cannot redirect a write
  outside that directory. The directory itself is not a valid output filename.
- Unsafe characters in source labels become `-`, and empty or `0` labels become
  `blocked`, preventing nginx directive injection and false allow decisions.
  Ordinary labels such as `ipsum-8`, `cn`, and `local` remain unchanged.
- Notification HTTP clients are separate from list-download validation, so
  private webhook endpoints and existing notification integrations still work.

## Build and CI

Builds require Go 1.27.1. CI reads the version from `go.mod`; the Docker builder
uses the same version. The binary is built without CGO. Build contexts include
only source and build inputs, excluding local configuration, credentials, and
Git history. Runtime Alpine packages are upgraded during image construction;
use `docker build --pull --no-cache` when rebuilding for newly published package
fixes so an old package-install layer is not reused.

GitHub Actions were updated to their latest published releases on 2026-09-11 and
pinned to commit hashes:

| Action | Release |
| --- | --- |
| actions/checkout | [v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) |
| actions/setup-go | [v7.0.0](https://github.com/actions/setup-go/releases/tag/v7.0.0) |
| docker/login-action | [v4.6.0](https://github.com/docker/login-action/releases/tag/v4.6.0) |
| docker/metadata-action | [v6.2.0](https://github.com/docker/metadata-action/releases/tag/v6.2.0) |
| docker/setup-qemu-action | [v4.3.0](https://github.com/docker/setup-qemu-action/releases/tag/v4.3.0) |
| docker/setup-buildx-action | [v4.3.0](https://github.com/docker/setup-buildx-action/releases/tag/v4.3.0) |
| docker/build-push-action | [v7.3.0](https://github.com/docker/build-push-action/releases/tag/v7.3.0) |
| ncipollo/release-action | [v1.21.0](https://github.com/ncipollo/release-action/releases/tag/v1.21.0) |

The workflows use GitHub-hosted `ubuntu-latest` runners. Keep any replacement
self-hosted runners compatible with these Actions' Node runtimes.

## Remaining trust boundaries

Direct Docker socket access grants control over the Docker host even when the
container runs without root. Capability limits and a read-only socket bind do
not constrain Docker API calls. For deployments that can reload nginx externally,
set `RESTART_CONTAINERS=false` and omit the socket mount, `DOCKER_HOST_GID`, and
`group_add`. Daily rule generation continues in this mode.

Remote sources and outbound proxies remain trusted configuration. DNS is checked
before each request and redirect; a DNS change between validation and connection
is still a residual risk. Restrict outbound access at the network layer where
that distinction matters. Set nginx's `set_real_ip_from` to the actual proxy
networks for your deployment, and configure the proxy to discard untrusted
forwarded headers.

See [Docker runtime security options](https://docs.docker.com/engine/containers/run/)
and [Go directory-scoped filesystem operations](https://pkg.go.dev/os#Root).

## Validation

```sh
go test ./...
go test -race -short ./...
go vet ./...
docker build --pull -t etr:hardening-test .
sh tests/docker-smoke.sh etr:hardening-test
docker scout cves etr:hardening-test
```

The smoke tests use disposable containers, fixture lists, no network access,
and no Docker socket. They verify user switching, protected application files,
GID mapping, generated rules, an actual scheduled cron update (up to 70 seconds),
and unprivileged nginx filtering, whitelist exclusions, logging, and reloads.

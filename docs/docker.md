# Docker setup

[Documentation index](../readme.md) · [Configuration](configuration.md) · [nginx integration](nginx.md)

The generator runs as UID 1000 in a `scratch` image without a shell. It schedules
feed refreshes in the Go process. nginx runs in a separate unprivileged container
and reads the shared rules volume.

## Quick start

Use Docker Engine with Compose v2. From a checkout of this repository:

1. Copy `config.example.json` to `config.json`. For the basic example, set
   `nginx_container_names` to `["nginx-blacklist"]`, which matches its explicit
   `container_name`. Choose feeds and local exemptions before deployment.
2. In `docker-compose.example.yml`, replace the `group_add` value with the
   Docker socket group ID on your host. On a typical Linux host, find it with
   `getent group docker`. This grants broad Docker API authority; see below.
3. Review `nginx/default.conf`, especially trusted proxy ranges and the empty
   User-Agent rule. The example mounts this file separately from generated rules.
4. Generate the initial list before starting nginx:

```bash
cp config.example.json config.json
# Edit config.json and docker-compose.example.yml before continuing.
docker compose -f docker-compose.example.yml run --rm --no-deps \
  -e RESTART_CONTAINERS=false emerging-threats-rules \
  /usr/local/bin/nginx_blacklist --force
```

Then start nginx and the scheduled generator:

```bash
docker compose -f docker-compose.example.yml up -d nginx-blacklist
docker compose -f docker-compose.example.yml up -d emerging-threats-rules
docker compose -f docker-compose.example.yml ps
```

This setup exposes no public port for the checker. Your reverse proxy must
reach nginx on its internal port 8080 and use `/check_ip` as its authorization
endpoint. Choose a [proxy example](../examples/README.md) for application routing.
`depends_on` alone does not wait for a generated rules file; the explicit first
run above avoids that startup race.

Verify the checker from inside nginx:

```bash
docker compose -f docker-compose.example.yml exec nginx-blacklist \
  wget -S -O - -U ETR-test http://localhost:8080/check_ip
# A normal User-Agent and an unblocked client address should receive 200.
```

Use [manual testing](../testing.md) for blocked addresses and forwarded headers.
The test shell belongs to the nginx container; the ETR image has no shell.

## Docker socket and external application

The supplied automatic-restart examples mount `/var/run/docker.sock`. Access to
that socket can grant host-level control on rootful Docker. Dropping container
capabilities or mounting the socket read-only does not limit API operations.

For generation without Docker API access:

- Set `RESTART_CONTAINERS=false`.
- Remove the socket volume and its `group_add` entry.
- Arrange validation and application through your deployment tooling.

The daemon continues scheduled refreshes in this mode. nginx keeps its loaded
rules until your workflow reloads or restarts it. Do not grant a downloader
write access to arbitrary configuration loaded by a privileged nginx process;
the [native root validator](../native-install.md#choose-who-applies-the-blocklist)
provides a restricted handoff for host installations.

## Files and container names

| File or volume | Generator | nginx |
| --- | --- | --- |
| `config.json` | Read-only at `/app/config.json` | Not needed |
| Rules volume | Writable at `/app/nginx/conf` | Read-only at `/etc/nginx/conf.d` |
| `nginx/default.conf` | Not needed | Separately mounted, read-only |

Fresh named volumes inherit the image directory's ownership. For a bind mount,
prepare a dedicated directory writable by UID 1000/GID 987. Do not grant write
access to nginx configuration directories shared with unrelated services.

`nginx_container_names` uses Docker runtime names, not necessarily Compose
service names. The example sets `container_name: nginx-blacklist`. The root
`docker-compose.yml` leaves naming to Compose; inspect `docker compose ps` and
set the config accordingly. Running an image in daemon mode keeps the process
alive; `--force` performs one feed refresh and exits.

## Logs

ETR writes operational logs to stdout. The nginx example writes blocked-request
JSON to its stdout log. Use:

```bash
docker compose -f docker-compose.example.yml logs --no-log-prefix -f \
  emerging-threats-rules nginx-blacklist
```

The basic example also defines an optional `log-manager` service and
`blocklist-logs` volume. These do nothing for stdout logs: configure nginx to
write `/var/log/blocklist/blocklist.log` before using that rotation workflow.
Give nginx's UID write access to the dedicated volume. Docker's logging-driver
limits handle stdout rotation separately. See [reporting](../reporting.md).

## Software upgrades

Review an image release, pin its tag or digest in Compose, then pull and recreate
the generator. The native self-updater and release checker do not run in Docker.
`mxmd/etr:v3` follows development builds as well as releases; it is not an
immutable production pin. See [release behavior](../releasing.md).

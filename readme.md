# Emerging Threat Rules for Nginx

Docker Hub: https://hub.docker.com/r/mxmd/etr

## Overview

This Dockerized Go application automates the generation of an Nginx `blocklist.conf` file from dynamic IP threat
lists. It runs as a daily cron job inside the container, downloading the latest blocked IPs and restarting the
companion nginx container(s) so the new rules take effect automatically.

The nginx container(s) exposes a single `/check_ip` endpoint used as a
[Traefik `forwardAuth`](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) target. Every request Traefik
forwards to your services first hits `/check_ip`; blocked IPs and empty User-Agents get a `403` and are dropped before
they reach your app.

---

## Quick Start

### 1. Copy the example config

```bash
cp config.example.json config.json
```

Edit `config.json` to set the container name(s) nginx will run as (see `nginx_container_names` below).

### 2. Find your host's Docker group ID

```bash
grep docker /etc/group | cut -d: -f3
```

Set `DOCKER_HOST_GID` in `docker-compose.yml` to that value.

### 3. Bring it up

```bash
docker compose up emerging-threats-rules   # runs once, writes blocklist.conf
docker compose up -d nginx-blacklist       # starts nginx with the blocklist
```

On subsequent days the cron job inside `emerging-threats-rules` refreshes the blocklist and restarts nginx
automatically.

---

## Configuration (`config.json`)

Copy `config.example.json` as a starting point:

```json
{
  "nginx_container_names": [
    "nginx-blacklist-1"
  ],
  "block_lists": [
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/8.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/7.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/6.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/4.txt",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  ],
  "nginx_conf_file_path": "/app/nginx/conf/blocklist.conf"
}
```

| Field | Description |
|---|---|
| `block_lists` | URLs to fetch. One IP/CIDR per line; `#` comments are ignored. Each URL becomes a blocklist label in logs. |
| `nginx_conf_file_path` | Where to write `blocklist.conf` inside the container. Must match the shared volume mount. |
| `nginx_container_names` | Container names to restart after updating the blocklist. Must match the names Docker assigns at runtime. |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DOCKER_HOST_GID` | _(unset)_ | GID of the `docker` group on the host. Required when using the Docker socket so the container user can access it. Find it with `grep docker /etc/group \| cut -d: -f3`. |
| `RUN_AS_ROOT` | `false` | Run the rule generator as root instead of the `anubis` user. Only needed in debugging scenarios or when the host docker GID conflicts with Alpine's reserved range. |
| `RESTART_CONTAINERS` | `true` | When `true` (default), uses the mounted Docker socket to restart the nginx containers listed in `config.json` after updating the blocklist. Set to `false` to skip all Docker socket access — the container will only write `blocklist.conf` and exit. The `docker.sock` volume mount can be omitted entirely in this mode. Use an external cron job or your orchestrator's reload mechanism to pick up the updated file. |

---

## Docker Compose

### Minimal example

Both services share a named volume (`nginx-blocking-rules`). The rule generator writes `blocklist.conf` into it; nginx
reads it on startup.

```yaml
version: '3'

services:
  emerging-threats-rules:
    environment:
      # Match the docker group GID on the host: grep docker /etc/group | cut -d: -f3
      - DOCKER_HOST_GID=1003
      - RUN_AS_ROOT=false
    image: mxmd/etr:v2
    build: .
    volumes:
      - ./config.json:/app/config.json:ro
      - nginx-blocking-rules:/app/nginx/conf/
      - /var/run/docker.sock:/var/run/docker.sock

  nginx-blacklist:
    depends_on:
      - emerging-threats-rules
    image: nginx:alpine
    volumes:
      - "nginx-blocking-rules:/etc/nginx/conf.d/"
      - "./nginx/default.conf:/etc/nginx/conf.d/default.conf"

volumes:
  nginx-blocking-rules:
```

### Traefik integration example

Wire Traefik's `forwardAuth` middleware to `/check_ip` and apply it globally (or per-router):

```yaml
services:
  traefik:
    healthcheck:
      test: ["CMD", "traefik", "healthcheck", "--ping"]
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: always
    image: "traefik:v2.11.0"
    container_name: "traefik"
    command:
      - "--ping=true"
      - "--entrypoints.ping.address=:8082"
      - "--log.level=DEBUG"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
      - "--entrypoints.web.http.redirections.entrypoint.permanent=true"
      - "--accesslog=true"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    labels:
      - "traefik.enable=true"
      # Define the global emerging-threat blocklist forwardAuth middleware
      - "traefik.http.middlewares.etr-blocklist.forwardauth.address=http://etr-blocker-nginx/check_ip"
    networks:
      - traefik-public

  etr-downloader:
    image: mxmd/etr
    restart: always
    environment:
      - DOCKER_HOST_GID=1003
      - RUN_AS_ROOT=false
    volumes:
      - ./etr/config.json:/app/config.json:ro
      - nginx-blocking-rules:/app/nginx/conf/
      - /var/run/docker.sock:/var/run/docker.sock

  etr-blocker-nginx:
    deploy:
      replicas: 2
    depends_on:
      - etr-downloader
    image: nginx:alpine
    restart: always
    volumes:
      - "nginx-blocking-rules:/etc/nginx/conf.d/"
      - "./etr/nginx/default.conf:/etc/nginx/conf.d/default.conf"
    networks:
      - traefik-public

volumes:
  nginx-blocking-rules:
```

To apply the middleware to a router, add a label to any service:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=etr-blocklist@docker"
```

---

## Nginx Configuration (`nginx/default.conf`)

The included `nginx/default.conf` is the companion to the generated `blocklist.conf` — both are required for blocking
to work.

### How the two files relate

Both files land in the nginx container's `/etc/nginx/conf.d/` directory via the shared named volume:

| File | Source | Purpose |
|---|---|---|
| `blocklist.conf` | Generated by this app, written to the named volume | Defines the `geo $blocked_source {}` block with every blocked IP/CIDR and its source label |
| `default.conf` | Mounted from `./nginx/default.conf` | Reads `$blocked_source`, exposes `/check_ip`, and configures logging |

Nginx loads both files from `conf.d/` on startup. The `geo` variable defined in `blocklist.conf` is available to
`default.conf` because they share the same nginx context.

### `$blocked_source`

The app writes a `geo $blocked_source { ... }` block into `blocklist.conf`. For every blocked IP or CIDR,
`$blocked_source` is set to a label identifying which blocklist(s) it came from (e.g. `ipsum-4`, `compromised-ips`, or
`ipsum-4+compromised-ips` when an IP appears in multiple lists). For all other IPs it is `""` (empty / falsy).

### Performance

Nginx's [`ngx_http_geo_module`](http://nginx.org/en/docs/http/ngx_http_geo_module.html) builds a **binary trie** (a
32-bit radix tree for IPv4) from `blocklist.conf` at startup. The official documentation is explicit about the
per-request cost:

> "Since variables are evaluated only when used, the mere existence of even a large number of declared 'geo' variables
> does not cause any extra costs for request processing."

When `$blocked_source` is referenced (as in the `if ($blocked_source)` check), nginx performs a single trie traversal:
at most **32 pointer-follow steps** for any IPv4 address regardless of how many entries the blocklist contains. A
100,000-entry list costs exactly the same to query as a 10-entry list.

**Memory**

Each internal trie node is 32 bytes on a 64-bit system — four `uintptr_t` fields (`left`, `right`, `parent`, `value`)
as defined in [`ngx_radix_node_t`](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c).
A `/32` host entry can require up to 32 nodes in the worst case (one per bit, no shared prefix). For 100,000 `/32`
entries with no shared prefixes that is at most ~100 MB. Real-world blocklists share large prefix ranges so actual
usage is substantially lower. CIDR entries with shorter prefixes (e.g. `/24`) use fewer nodes and cover more
addresses.

**vs. `allow`/`deny`**

The `allow`/`deny` directives evaluate rules sequentially — O(n) per request. The `geo` module is O(32) regardless of
list size. The official docs note this distinction when recommending `geo` for large datasets.

**Reload cost**

The trie is rebuilt from text on every nginx restart or reload — this is the operationally meaningful cost, not
per-request lookup. The official docs recommend:

> "To speed up loading of a geo base, addresses should be put in ascending order."

This project already sorts entries in ascending order before writing `blocklist.conf`.

### `/check_ip` endpoint

`default.conf` exposes a single location used as a Traefik `forwardAuth` target:

1. **Empty User-Agent** — requests with no `User-Agent` header are blocked first (`$blocked_ua = "empty-ua"`).
2. **IP blocklist** — if `$blocked_source` is non-empty, the request is blocked.
3. **Allow** — all other requests return `200 OK`.

### Log format

Logs are emitted as JSON for easy ingestion by Datadog or any structured log pipeline:

```nginx
log_format blocklist escape=json
    '{"ip":"$remote_addr",'
     '"time":"$time_iso8601",'
     '"method":"$display_method",'
     '"url":"$display_url",'
     '"status":$status,'
     '"blocked_source":"$blocked_source",'
     '"blocked_ua":"$blocked_ua"}';
```

Only blocked requests (non-200) are written to the log. Allowed requests produce no log entry.

`X-Forwarded-Method`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri` are used to reconstruct the
real client-facing `method` and `url`. `blocked_source` is a `+`-joined label of every blocklist the IP appeared in.
`blocked_ua` is `empty-ua` for requests blocked by a missing User-Agent, otherwise empty.

Example log line:

```json
{"ip":"1.2.3.4","time":"2026-03-14T14:44:54+00:00","method":"GET","url":"https://example.com/api/v1/secret","status":403,"blocked_source":"ipsum-4+ipsum-3+ipsum-2","blocked_ua":""}
```

### Real IP trust

```nginx
real_ip_header    X-Forwarded-For;
set_real_ip_from  172.0.0.0/8;
real_ip_recursive on;
```

When nginx sits behind a Docker-internal proxy (Traefik, another nginx, etc.), `$remote_addr` would otherwise be the
proxy's container IP. This tells nginx to trust `X-Forwarded-For` from the entire `172.x.x.x` Docker network range so
`$remote_addr` — and therefore the geo lookup — reflects the real client IP.

`real_ip_recursive on` handles the case where `X-Forwarded-For` contains a chain of IPs, e.g.
`X-Forwarded-For: <real-client>, <internal-proxy>`. Without it, nginx uses the rightmost address in the header
(the last hop), which is often another trusted proxy rather than the actual client. With `real_ip_recursive on`, nginx
walks the list from right to left and skips addresses that match `set_real_ip_from`, stopping at the first
non-trusted address — which is the real client IP.

Adjust `set_real_ip_from` to match your internal network if you use a different subnet.

---

## Related Docs

- [reporting.md](reporting.md) — Query and analyze blocked request logs with `jq`
- [testing.md](testing.md) — Manually test the blocklist and nginx behavior locally

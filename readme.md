# Emerging Threat Rules for Nginx

Pulls daily-refreshed threat intelligence IP lists and generates a `blocklist.conf` for nginx. Wire it as a Traefik `forwardAuth` gate — every inbound request hits nginx's `/check_ip` first. Blocked IPs and headless bots get a `403` before they reach your app.

Docker Hub: https://hub.docker.com/r/mxmd/etr

---

## How It Works

**Allowed — 200 OK**

```
                    ┌────────────────────────────────┐
                    │  etr (daily cron)              │
                    │  IP lists → blocklist.conf     │
                    └───────────────┬────────────────┘
                                    │ shared volume
                                    ▼
 Client           Traefik        nginx /check_ip        app
   │                 │                  │                 │
   ├── request ─────►│                  │                 │
   │                 ├── forwardAuth ──►│                 │
   │                 │◄─── 200 OK ──────┤                 │
   │                 ├──────────────────────── forward ──►│
   │                 │◄─────────────────────── response ──┤
   │◄── response ────┤                  │                 │
```

**Blocked — 403**

```
 Client           Traefik        nginx /check_ip
   │                 │                  │
   ├── request ─────►│                  │
   │                 ├── forwardAuth ──►│
   │                 │◄─── 403 ─────────┤  ← blocked IP or empty User-Agent
   │◄── 403 ─────────┤                  │
```

1. `emerging-threats-rules` fetches the configured IP/CIDR lists once a day, merges and de-duplicates them, sorts them in ascending order, and writes `blocklist.conf` to a shared Docker volume.
2. Nginx loads that file on startup and holds the blocklist as an in-memory radix tree.
3. Traefik's `forwardAuth` middleware sends every request to nginx `/check_ip` before routing upstream. Blocked IPs and empty User-Agents return `403`; everything else returns `200` and traffic continues normally.

---

## Why `ngx_http_geo_module` (Not `allow`/`deny`)

The `geo` module is why this works at scale without adding meaningful latency.

| Approach | Per-request cost | 100k-entry list |
|---|---|---|
| `allow` / `deny` directives | O(n) — linear scan | 100,000 comparisons per request |
| `ngx_http_geo_module` | O(32) — radix tree | 32 pointer-follows, always |

Nginx builds a **32-bit radix tree** (binary trie) from `blocklist.conf` at startup. Looking up any IPv4 address walks at most 32 nodes — one per IP address bit. The lookup cost is constant regardless of list size. A 100,000-entry blocklist costs the same to query as a 10-entry one.

The official nginx docs confirm this:

> "Since variables are evaluated only when used, the mere existence of even a large number of declared 'geo' variables does not cause any extra costs for request processing."

**Memory:** each trie node is 32 bytes on a 64-bit system. Worst case (100k `/32` entries with no shared prefixes) is ~100 MB. Real-world threat lists share large prefix ranges, so actual usage is typically a few MB.

**The one meaningful cost is reload, not lookup.** When `emerging-threats-rules` restarts nginx with a refreshed list, the trie rebuilds from text — but this happens once a day. This project writes entries in ascending order (as the nginx docs recommend) to keep that rebuild fast.

The `forwardAuth` hop itself is a loopback call to a local container doing a pure in-memory lookup. Added latency per request is sub-millisecond.

---

## Quick Start

Official images are published to Docker Hub for **amd64 and arm64** — no repo clone required.

```bash
docker pull mxmd/etr:v2
```

### 1. Create `config.json`

Copy `config.example.json` from the repo or create it from scratch. At minimum, set `nginx_container_names` to match what Docker will name your nginx container — the service name from your compose file:

```json
{
  "nginx_container_names": ["nginx-blacklist"],
  "block_lists": [
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/6.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/4.txt",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  ],
  "nginx_conf_file_path": "/app/nginx/conf/blocklist.conf"
}
```

The ipsum levels are tiered by threat confidence (8 = highest, 4 = moderate). Start with levels 4–6 for broad coverage; tighten to 6–8 if you see false positives.

### 2. Find your host's Docker group ID

The rule generator needs the Docker socket to restart nginx after each daily refresh:

```bash
grep docker /etc/group | cut -d: -f3
# e.g. 1003
```

Set `DOCKER_HOST_GID` in `docker-compose.yml` to that value.

### 3. Bring it up

```bash
# Fetch the blocklists and write blocklist.conf (runs once, then exits)
docker compose up emerging-threats-rules

# Start nginx with the generated blocklist
docker compose up -d nginx-blacklist
```

The cron job inside `emerging-threats-rules` refreshes the blocklist and restarts nginx automatically every day.

### 4. Verify it's working

```bash
# Allowed request — expect 200
docker exec -it nginx-blacklist curl -s -o /dev/null -w "%{http_code}" localhost/check_ip

# Empty User-Agent — always blocked, expect 403
docker exec -it nginx-blacklist curl -s -o /dev/null -w "%{http_code}" -A "" localhost/check_ip
```

Watch live blocks:

```bash
docker logs -f nginx-blacklist
```

See [testing.md](testing.md) for how to spoof specific IPs against the live blocklist.

---

## Configuration (`config.json`)

| Field | Description |
|---|---|
| `nginx_container_names` | Container names to restart after updating. Must match Docker's runtime name (the service name from compose). |
| `block_lists` | URLs to fetch for blocking. One IP or CIDR per line; `#` comments are ignored. Each URL becomes a source label in logs (e.g. `ipsum-6`, `compromised-ips`). |
| `local_blocklist` | Static IPs/CIDRs to always block, defined inline in the config. |
| `local_whitelist` | Static IPs/CIDRs to never block, defined inline in the config. Takes precedence over all blocklists. |
| `remote_whitelists` | URLs to fetch for whitelisting. Same format as `block_lists`. |
| `nginx_conf_file_path` | Where to write `blocklist.conf` inside the container. Must match the shared volume mount. |

Full default config for reference:

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
  "local_whitelist": [],
  "local_blocklist": [],
  "remote_whitelists": [],
  "nginx_conf_file_path": "/app/nginx/conf/blocklist.conf"
}
```

---

## Whitelisting

Whitelisted IPs and CIDRs are **always allowed**, regardless of what any blocklist says. Use this to protect known-good addresses — monitoring infrastructure, CDN egress ranges, internal scanners — from being accidentally blocked.

### How it works: CIDR splitting

The naive approach to whitelisting is to skip a blocked entry entirely when it overlaps a whitelist entry. That would un-block an entire CIDR range just to protect a handful of IPs inside it.

Instead, this project uses **CIDR splitting**: when a whitelist entry is a subset of a blocked CIDR, the app carves the whitelisted addresses out of the blocked range and emits the minimal set of smaller CIDRs that cover exactly the blocked portion.

Example — blocklist contains `198.51.100.0/24`, whitelist contains `198.51.100.5`:

```
Blocked:    198.51.100.0/24   (256 addresses)
Whitelisted: 198.51.100.5

Result written to blocklist.conf:
    198.51.100.0/30     # .0–.3   blocked
    198.51.100.4/32     # .4      blocked
    # .5 omitted — whitelisted
    198.51.100.6/31     # .6–.7   blocked
    198.51.100.8/29     # .8–.15  blocked
    ... (minimal CIDR cover continues through .255)
```

The log line for a split will tell you exactly what happened:

```
Splitting blocklist CIDR 198.51.100.0/24 (from compromised-ips): retaining 8 sub-ranges after whitelist exclusions
```

If an entry is fully covered by the whitelist, it is dropped entirely with a log message:

```
Skipping whitelisted IP: 1.2.3.4 (matched: 1.2.3.0/24 from local_whitelist) - found in blocklist: ipsum-6
```

### Configuration

```json
{
  "nginx_container_names": ["nginx-blacklist"],
  "block_lists": [
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  ],
  "local_whitelist": [
    "1.2.3.4",
    "203.0.113.0/28"
  ],
  "remote_whitelists": [
    "https://example.com/my-cdn-egress-ips.txt"
  ],
  "nginx_conf_file_path": "/app/nginx/conf/blocklist.conf"
}
```

Whitelist sources are processed in this order of precedence (all equal — any match wins):

| Source | Field | Use case |
|---|---|---|
| Inline IPs/CIDRs | `local_whitelist` | A handful of known-good IPs you manage directly |
| Remote list | `remote_whitelists` | CDN egress ranges, monitoring vendor IPs, etc. |

---

## Notifications

The app can alert you via Telegram, email (SMTP/STARTTLS), or a generic webhook when something goes wrong. Two events trigger a notification:

1. **Blocklist update abandoned** — when the percentage of failed remote blocklist downloads reaches `BLOCKLIST_FAILURE_THRESHOLD` (default 30%). The existing `blocklist.conf` is preserved rather than overwriting it with incomplete data.
2. **Nginx restart failed** — when a configured container cannot be restarted after a blocklist update.

Configure one or more channels via environment variables (see the table below). Channels are independent — set whichever you need; partially configured channels (e.g. a Telegram token with no chat ID) are skipped with a warning rather than failing.

```yaml
environment:
  - INSTANCE_NAME=prod-eu          # optional label in alert subject
  - TELEGRAM_BOT_TOKEN=123:abc
  - TELEGRAM_CHAT_ID=-1001234567890
  # or SMTP / WEBHOOK_URL instead
```

---

## Environment Variables

### General

| Variable | Default | Description |
|---|---|---|
| `DOCKER_HOST_GID` | _(unset)_ | GID of the `docker` group on the host. Required for socket access. Find with `grep docker /etc/group \| cut -d: -f3`. |
| `RUN_AS_ROOT` | `false` | Run as root instead of the `anubis` user. Only needed when the host docker GID conflicts with Alpine's reserved range. |
| `RESTART_CONTAINERS` | `true` | When `false`, skips all Docker socket access — only writes `blocklist.conf` and exits. Omit the `docker.sock` volume mount entirely in this mode. Use an external cron job or your orchestrator's reload hook to apply the updated file. |
| `BLOCKLIST_FAILURE_THRESHOLD` | `30` | Percentage of remote blocklist sources that must fail before the update is abandoned and the existing blocklist preserved. Set to `0` to always write even on partial failures; `100` to never abort early. |
| `INSTANCE_NAME` | _(unset)_ | Optional label added to notification subjects — e.g. `[ETR prod-eu]`. Useful when running multiple deployments. |

### Notifications

Alerts fire when: (1) enough remote blocklist sources fail that the threshold is exceeded and the update is abandoned, or (2) a configured nginx container fails to restart.

**Telegram**

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | _(unset)_ | Bot token from @BotFather. Both token and chat ID must be set to enable Telegram. |
| `TELEGRAM_CHAT_ID` | _(unset)_ | Target chat or channel ID. |

**Email (SMTP / STARTTLS)**

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | _(unset)_ | SMTP server hostname. All three of host, from, and to must be set to enable email. |
| `SMTP_PORT` | `587` | SMTP port (STARTTLS). |
| `SMTP_FROM` | _(unset)_ | Sender address. |
| `SMTP_TO` | _(unset)_ | Comma-separated list of recipient addresses. |
| `SMTP_USER` | _(unset)_ | SMTP username — omit for unauthenticated relay. |
| `SMTP_PASS` | _(unset)_ | SMTP password. |

**Webhook**

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | _(unset)_ | URL to POST `{"subject":"…","body":"…"}` (JSON) on notable events. |

---

## Docker Compose

### Minimal example

Both services share a named volume. The rule generator writes `blocklist.conf`; nginx reads it on startup. A third `log-manager` container rotates the nginx blocklist log daily so it doesn't grow unbounded.

```yaml
version: '3'

services:
  emerging-threats-rules:
    image: mxmd/etr:v2
    environment:
      - DOCKER_HOST_GID=1003   # grep docker /etc/group | cut -d: -f3
    volumes:
      - ./config.json:/app/config.json:ro
      - nginx-blocking-rules:/app/nginx/conf/
      - /var/run/docker.sock:/var/run/docker.sock

  nginx-blacklist:
    image: nginx:alpine
    depends_on:
      - emerging-threats-rules
    volumes:
      - nginx-blocking-rules:/etc/nginx/conf.d/
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf
      - nginx-logs:/var/log/nginx
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "7"

  log-manager:
    depends_on:
      - nginx-blacklist
    build: ./log-manager
    restart: unless-stopped
    volumes:
      - nginx-logs:/var/log/nginx

volumes:
  nginx-blocking-rules:
  nginx-logs:
```

### Traefik integration

Define the `forwardAuth` middleware in Traefik's labels, then apply it to any router.

```yaml
services:
  traefik:
    image: traefik:v2.11.0
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    labels:
      - "traefik.enable=true"
      # Register the blocklist middleware — points at the nginx checker
      - "traefik.http.middlewares.etr-blocklist.forwardauth.address=http://etr-blocker-nginx/check_ip"
    networks:
      - traefik-public

  etr-downloader:
    image: mxmd/etr
    restart: always
    environment:
      - DOCKER_HOST_GID=1003
    volumes:
      - ./etr/config.json:/app/config.json:ro
      - nginx-blocking-rules:/app/nginx/conf/
      - /var/run/docker.sock:/var/run/docker.sock

  etr-blocker-nginx:
    image: nginx:alpine
    restart: always
    deploy:
      replicas: 2
    depends_on:
      - etr-downloader
    volumes:
      - nginx-blocking-rules:/etc/nginx/conf.d/
      - ./etr/nginx/default.conf:/etc/nginx/conf.d/default.conf
    networks:
      - traefik-public

volumes:
  nginx-blocking-rules:
```

Apply the middleware to any service with a single label:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=etr-blocklist@docker"
```

---

## Nginx Configuration (`nginx/default.conf`)

The included `nginx/default.conf` and the generated `blocklist.conf` both land in `/etc/nginx/conf.d/` via the shared volume.

| File | Source | Purpose |
|---|---|---|
| `blocklist.conf` | Generated daily by this app | Defines `geo $blocked_source {}` — the radix tree of every blocked IP/CIDR and its source label |
| `default.conf` | Mounted from `./nginx/default.conf` | Reads `$blocked_source`, exposes `/check_ip`, configures logging |

### `$blocked_source`

For every blocked IP or CIDR, `$blocked_source` is set to a label identifying which list(s) it came from — e.g. `ipsum-6`, `compromised-ips`, or `ipsum-6+compromised-ips` when an IP appears in multiple lists. For all other IPs it is `""` (empty/falsy).

### `/check_ip` block logic

| Condition | Variable set | Response |
|---|---|---|
| Empty `User-Agent` header | `$blocked_ua = "empty-ua"` | 403 |
| IP matched in blocklist | `$blocked_source = "<label>"` | 403 |
| Neither | both empty | 200 OK |

Empty UA is checked first. Only blocked requests (non-200) are written to the log.

### Log format

Logs are JSON for easy ingestion by Datadog or any structured log pipeline:

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

Example log line:

```json
{"ip":"1.2.3.4","time":"2026-03-14T14:44:54+00:00","method":"GET","url":"https://example.com/api/v1/secret","status":403,"blocked_source":"ipsum-4+ipsum-3+ipsum-2","blocked_ua":""}
```

`X-Forwarded-Method`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri` are used to reconstruct the real client-facing `method` and `url`. `blocked_source` is a `+`-joined label of every blocklist the IP appeared in.

### Real IP trust

```nginx
real_ip_header      X-Forwarded-For;
real_ip_recursive   on;
set_real_ip_from    10.0.0.0/8;      # Docker host networking & overlay networks
set_real_ip_from    172.16.0.0/12;   # Docker default bridge networks (172.16–172.31)
set_real_ip_from    192.168.0.0/16;  # Docker custom bridge networks
```

When nginx sits behind Traefik (or another Docker-internal proxy), `$remote_addr` would be the proxy's container IP without this config. These three ranges cover all standard Docker networking modes so the geo lookup always operates on the real client IP.

`real_ip_recursive on` handles chained proxies: nginx walks `X-Forwarded-For` right-to-left, skips addresses matching any `set_real_ip_from` range, and stops at the first untrusted address — the actual client.

> **CPU note:** `real_ip_recursive on` scans the full `X-Forwarded-For` chain on every request. An attacker can send an arbitrarily long XFF header, forcing a linear scan before nginx resolves the real IP. Nginx's `large_client_header_buffers` bounds the worst case (default 8 KB / 4 buffers), but if you see elevated CPU on `etr-blocker-nginx` consider stripping or truncating `X-Forwarded-For` at the Traefik layer before the forwardAuth hop.

Adjust `set_real_ip_from` ranges to match your network topology.

---

## Examples

Alternative configurations for setups that don't use Traefik:

| Example | Description |
|---|---|
| [`examples/traefik-v2/`](examples/traefik-v2/) | Traefik v2 with `forwardAuth` to the nginx checker |
| [`examples/traefik-v3/`](examples/traefik-v3/) | Traefik v3 — same pattern; notes HTTP/3 opt-in and API changes |
| [`examples/caddy/`](examples/caddy/) | Caddy `forward_auth` to the nginx checker (Caddy sends identical `X-Forwarded-*` headers) |
| [`examples/nginx-reverse-proxy/`](examples/nginx-reverse-proxy/) | nginx is both edge proxy and blocker — geo check inline before `proxy_pass`, no separate forwardAuth hop |
| [`examples/pfsense/`](examples/pfsense/) | pfSense HAProxy as edge → nginx inline blocking → app; includes HAProxy configuration steps |

---

## Related Docs

- [reporting.md](reporting.md) — Query and analyze blocked request logs with `jq`
- [testing.md](testing.md) — Manually test the blocklist and nginx behavior locally

---

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).

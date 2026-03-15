# Log Reporting with jq

Logs are emitted as newline-delimited JSON. All queries below parse the log stream with this base pattern:

```bash
jq -Rn '[inputs | try fromjson | select(type == "object")]'
```

`-R` reads each line as a raw string, `try fromjson` discards non-JSON lines (empty lines, container prefixes), `-n` with `inputs` processes the full stream lazily.

## Getting Logs

Blocked requests are written to two places:

- **Docker stdout** — captured by the Docker logging driver. Use `docker logs` to read it.
- **`/var/log/nginx/blocklist.log`** — persisted to the `nginx-logs` shared volume and rotated daily by the `log-manager` service. Useful for offline analysis across restarts or longer time windows.

**Single container (stdout):**
```bash
docker logs <container-name> 2>&1
```

**Docker Compose** (requires Compose v2 — strips the `service | ` prefix):
```bash
docker compose logs nginx-blacklist --no-log-prefix 2>&1
```

**From the persisted log file:**
```bash
docker exec nginx-blacklist cat /var/log/nginx/blocklist.log
```

All query examples below use `docker logs <container>` — substitute the log file path for offline analysis against the rotated file.

---

## Live / Streaming Logs

To watch blocked requests in real time, use `jq -R --unbuffered` (processes one line as it arrives instead of
buffering the whole stream).

Docker Compose adds a `service-name | ` prefix to every log line. Strip it with `awk '{print $NF}'` before piping to
`jq`. `stdbuf -oL` forces line-buffered output so nothing sits in awk's buffer:

```bash
docker-compose -f /path/to/docker-compose.yml logs etr-blocker-nginx -f 2>&1 \
  | stdbuf -oL awk '{print $NF}' \
  | jq -R --unbuffered 'try fromjson | select(type == "object")'
```

Or with Compose v2's `--no-log-prefix` flag (skips the awk step):

```bash
docker compose logs etr-blocker-nginx --no-log-prefix -f 2>&1 \
  | jq -R --unbuffered 'try fromjson | select(type == "object")'
```

> `--no-log-prefix` is a Compose v2 flag and may not be available in all CI environments or older installs. The
> `stdbuf -oL awk '{print $NF}'` approach works universally.

Each blocked request prints as it happens:

```json
{"ip":"1.2.3.4","time":"2026-03-14T14:44:54+00:00","method":"GET","url":"https://example.com/secret","status":403,"blocked_source":"ipsum-4","blocked_ua":""}
```

---

## Queries

### Count total blocked requests
```bash
docker logs <container> 2>&1 \
  | jq -Rn '[inputs | try fromjson | select(type == "object")] | length'
```

### Unique blocked IPs
```bash
docker logs <container> 2>&1 \
  | jq -Rn '[inputs | try fromjson | select(type == "object") | .ip] | unique | length'
```

### Block reason split
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object")] as $all |
    {
      blocked_by_ip:       ($all | map(select(.blocked_source != "")) | length),
      blocked_by_empty_ua: ($all | map(select(.blocked_ua    != "")) | length)
    }'
```

### Top blocked IPs
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object")]
    | group_by(.ip)
    | map({ip: .[0].ip, hits: length})
    | sort_by(-.hits)
    | .[:10]'
```

### Top blocklist sources
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object") | select(.blocked_source != "")]
    | group_by(.blocked_source)
    | map({source: .[0].blocked_source, hits: length})
    | sort_by(-.hits)'
```

### Top targeted URLs
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object")]
    | group_by(.url)
    | map({url: .[0].url, hits: length})
    | sort_by(-.hits)
    | .[:10]'
```

### Top targeted hosts
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object")]
    | map(.url | capture("https?://(?<host>[^/?]+)").host)
    | group_by(.)
    | map({host: .[0], hits: length})
    | sort_by(-.hits)'
```

### Requests by method
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object")]
    | group_by(.method)
    | map({method: .[0].method, hits: length})
    | sort_by(-.hits)'
```

---

## Filters

### By blocklist label
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object") | select(.blocked_source | contains("ipsum"))]'
```

### Empty User-Agent blocks only
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object") | select(.blocked_ua != "")]'
```

### Specific IP
```bash
docker logs <container> 2>&1 \
  | jq -Rn '
    [inputs | try fromjson | select(type == "object") | select(.ip == "1.2.3.4")]'
```

---

## Offline Analysis

Capture logs to a file first when running multiple queries against the same window:

```bash
docker logs <container> 2>&1 | jq -Rc 'try fromjson | select(type == "object")' > blocked.json
```

Or read directly from the persisted log volume (no container restart needed):

```bash
docker exec nginx-blacklist cat /var/log/nginx/blocklist.log \
  | jq -Rc 'try fromjson | select(type == "object")' > blocked.json
```

Then query the file directly:

```bash
jq -Rn '[inputs | try fromjson] | group_by(.ip) | map({ip: .[0].ip, hits: length}) | sort_by(-.hits)' blocked.json
```

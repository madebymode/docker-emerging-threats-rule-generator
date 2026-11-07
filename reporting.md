# Log Reporting with jq

[Documentation index](readme.md) · [nginx integration](docs/nginx.md)

Logs are emitted as newline-delimited JSON. All queries below parse the log stream with this base pattern:

```bash
jq -Rn '[inputs | try fromjson | select(type == "object")]'
```

`-R` reads each line as a raw string, `try fromjson` discards non-JSON lines (empty lines, container prefixes), `-n` with `inputs` processes the full stream lazily.

## Getting Logs

The default Docker nginx configuration writes blocked-request JSON to stdout.
The Docker logging driver handles its retention. ETR's own operational logs are
separate text records; native services send those records to journald.

File logs are optional. If you configure nginx to write
`/var/log/blocklist/blocklist.log` on the `blocklist-logs` volume, the optional
`log-manager` service rotates that file. Mounting the volume alone does not
create file logging. Native request logging must also be configured explicitly;
see [native logging](native-install.md#4-enforcement-and-block-logging).

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
docker exec nginx-blacklist cat /var/log/blocklist/blocklist.log
```

All query examples below use `docker logs <container>` — substitute the log file path for offline analysis against the rotated file.

---

## Live / Streaming Logs

To watch blocked requests in real time, use `jq -R --unbuffered` (processes one line as it arrives instead of
buffering the whole stream).

Use Compose v2's `--no-log-prefix` so the JSON remains intact. Do not strip
prefixes with `awk '{print $NF}'`: that loses data when JSON values contain spaces.

```bash
docker compose logs etr-blocker-nginx --no-log-prefix -f 2>&1 \
  | jq -R --unbuffered 'try fromjson | select(type == "object")'
```

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

If file logging is configured, read from its volume (no restart needed):

```bash
docker exec nginx-blacklist cat /var/log/blocklist/blocklist.log \
  | jq -Rc 'try fromjson | select(type == "object")' > blocked.json
```

Then query the file directly:

```bash
jq -Rn '[inputs | try fromjson] | group_by(.ip) | map({ip: .[0].ip, hits: length}) | sort_by(-.hits)' blocked.json
```

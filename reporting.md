# Log Reporting with jq

Logs are emitted as newline-delimited JSON. All queries below parse the log stream with this base pattern:

```bash
jq -Rn '[inputs | try fromjson | select(type == "object")]'
```

`-R` reads each line as a raw string, `try fromjson` discards non-JSON lines (empty lines, container prefixes), `-n` with `inputs` processes the full stream lazily.

## Getting Logs

**Single container:**
```bash
docker logs <container-name> 2>&1
```

**Docker Compose** (requires Compose v2 — strips the `service | ` prefix):
```bash
docker compose logs nginx-blacklist --no-log-prefix 2>&1
```

All examples below use `docker logs <container>` — substitute with the compose variant as needed.

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

Then query the file directly:

```bash
jq -Rn '[inputs | try fromjson] | group_by(.ip) | map({ip: .[0].ip, hits: length}) | sort_by(-.hits)' blocked.json
```

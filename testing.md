# Testing the Nginx Blocklist Locally

This document covers how to manually test the nginx blocklist behavior without a Traefik/forward auth setup in front of it.

## Prerequisites

The `emerging-threats-rules` service must have run at least once so `blocklist.conf` is written to the shared volume before nginx starts.

```bash
docker compose up emerging-threats-rules
docker compose up nginx-blacklist
```

## Exec Into the Container

```bash
docker exec -it <nginx-container-name> sh
```

From inside the container you can hit `localhost` directly — no port mapping needed.

---

## Note: Trusting the Proxy for Forwarded Headers

By default, `set_real_ip_from` in `default.conf` only trusts `X-Forwarded-For` headers from `172.0.0.0/8` (internal Docker networks). When curling from inside the container, the connecting IP is `127.0.0.1` — which is not in that range — so nginx ignores the XFF header and `$remote_addr` stays as `127.0.0.1`.

To spoof IPs via `X-Forwarded-For` during local testing, patch the config to also trust localhost:

```bash
sed -i 's/set_real_ip_from 172.0.0.0\/8;/set_real_ip_from 172.0.0.0\/8;\nset_real_ip_from 127.0.0.1;/' /etc/nginx/conf.d/default.conf
nginx -s reload
```

> This patch is temporary — it only affects the running container and is lost on restart.

---

## Basic Tests

**Allowed request (expect 200):**
```bash
curl -s localhost/check_ip
```

**Empty User-Agent — triggers `$blocked_ua` (expect 403):**
```bash
curl -s -A "" localhost/check_ip
```

---

## Testing With Full Log Context

The nginx log format uses Traefik-forwarded headers to reconstruct the original client URL. Set them to get meaningful log output:

```bash
curl -s -A "" \
  -H "X-Forwarded-Method: GET" \
  -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Host: myapp.example.com" \
  -H "X-Forwarded-Uri: /admin/login" \
  localhost/check_ip
```

Expected log line:
```
127.0.0.1 - [14/Mar/2026:12:00:00 +0000] "GET https://myapp.example.com/admin/login" 403 blocked_by="empty-ua"
```

> Only non-200 responses are logged (controlled by the `$loggable` map in `default.conf`).

---

## Testing IP Blocking

After applying the localhost trust patch above, spoof a blocked IP via `X-Forwarded-For`:

```bash
curl -s \
  -H "X-Forwarded-For: 1.2.3.4" \
  -H "X-Forwarded-Method: GET" \
  -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Host: myapp.example.com" \
  -H "X-Forwarded-Uri: /secret" \
  localhost/check_ip
```

Expected log line (if `1.2.3.4` is in the blocklist):
```
1.2.3.4 - [14/Mar/2026:12:00:00 +0000] "GET https://myapp.example.com/secret" 403 blocked_by="<blocklist-label>"
```

**Verify an IP is in the generated blocklist:**
```bash
grep "1.2.3.4" /etc/nginx/conf.d/blocklist.conf
```

---

## Watching Logs Live

From outside the container:
```bash
docker logs -f <nginx-container-name>
```

---

## How the Block Logic Works

| Condition | Variable | Response |
|---|---|---|
| Empty `User-Agent` header | `$blocked_ua = "empty-ua"` | 403 |
| IP matched in `blocklist.conf` geo block | `$blocked_source = "<label>"` | 403 |
| Neither | both empty/falsy | 200 OK |

The `blocked_by=` field in the log will contain whichever variable was non-empty. Empty UA is checked first.

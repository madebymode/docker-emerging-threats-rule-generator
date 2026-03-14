# pfSense HAProxy Example

Traffic flow:

```
Internet → pfSense HAProxy (WAN) → Docker host nginx (LAN) → your app
```

pfSense HAProxy acts as the TLS-terminating edge. It forwards plaintext HTTP
to the nginx container, which performs the geo blocklist and User-Agent checks
before proxying to your application.

---

## Docker side

```bash
# 1. Find your Docker host's docker group GID
grep docker /etc/group | cut -d: -f3

# 2. Set DOCKER_HOST_GID in docker-compose.yml to that value

# 3. Edit nginx/default.conf
#    - Update set_real_ip_from to your pfSense LAN interface IP
#    - Update the upstream block to point at your application

# 4. Bring it up
docker compose up -d
```

By default, nginx binds to `127.0.0.1:8080`. If pfSense is on a separate
machine (the common case), change the port binding in `docker-compose.yml` to
your Docker host's LAN IP so HAProxy can reach it:

```yaml
ports:
  - "192.168.1.50:8080:80"   # replace with your Docker host's LAN IP
```

---

## pfSense HAProxy configuration

Install the HAProxy package if not already present:
**System > Package Manager > Available Packages → haproxy**

### Backend

**Services > HAProxy > Backend** — click **Add**

| Field | Value |
|---|---|
| Name | `etr-backend` |
| Balance | `roundrobin` (or `leastconn`) |
| Server list → Address | Docker host LAN IP (e.g. `192.168.1.50`) |
| Server list → Port | `8080` (or whatever port nginx binds to) |
| **Forwardfor** | ✅ Enable ("httpclose" or "forwardfor" option) |

Enabling **Forwardfor** makes HAProxy insert `X-Forwarded-For: <client-ip>`
so nginx can resolve `$remote_addr` to the real client instead of pfSense.

> **Spoofing hardening:** also enable **"Forwardfor except"** and set it to
> pfSense's WAN interface IP. This causes HAProxy to *replace* any existing
> `X-Forwarded-For` header rather than append to it, preventing clients from
> injecting a forged XFF chain to bypass the blocklist.

### Frontend

**Services > HAProxy > Frontend** — click **Add**

| Field | Value |
|---|---|
| Name | `etr-frontend` |
| Status | `Active` |
| Bind addresses | WAN address, port `80` (and/or `443` with TLS offload) |
| Default backend | `etr-backend` |

For HTTPS, add a certificate under **Bind SSL** and let pfSense handle TLS
termination. nginx receives plain HTTP from HAProxy on port 8080.

### Apply

Click **Save**, then **Services > HAProxy > Apply Changes**.

---

## Verifying real IP resolution

After bringing up both sides, check that nginx sees the client IP (not pfSense):

```bash
# From a machine behind pfSense, curl the docker host directly:
curl -v http://192.168.1.50:8080/

# Check nginx logs — $remote_addr should be your client IP, not 192.168.1.1
docker compose logs nginx
```

If `$remote_addr` still shows pfSense's IP, confirm that:
1. HAProxy's Forwardfor option is enabled and saved.
2. `set_real_ip_from` in `nginx/default.conf` matches your pfSense LAN IP.
3. The nginx container was restarted after the config change.

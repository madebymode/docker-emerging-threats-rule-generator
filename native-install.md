# Native Install (no Docker)

The native build runs ETR directly on an nginx host as a systemd service. It is
one static binary with no runtime dependencies. It runs updates on its own
schedule (default 03:00 local, up to 60 min jitter), validates every new
blocklist with `nginx -t`, and applies it with `systemctl reload-or-restart`:
a graceful reload that drops no connections where the nginx unit supports one,
and a restart otherwise (ServerPilot's `nginx-sp`). If validation or reload
fails, it restores the previous blocklist.

| Platform | nginx | Unit file |
|---|---|---|
| Ubuntu 20.04 / 22.04 / 24.04 with ServerPilot | `nginx-sp` | [`etr-serverpilot.service`](deploy/systemd/etr-serverpilot.service) |
| Ubuntu 20.04+ with distro or nginx.org nginx | `nginx` | [`etr.service`](deploy/systemd/etr.service) |
| RHEL 8 / 9 / 10, Rocky, AlmaLinux, Oracle Linux | `nginx` | [`etr.service`](deploy/systemd/etr.service) |

All commands below run as root (`sudo -i`).

---

## 1. Install the binary (all platforms)

```bash
case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac

REPO=madebymode/docker-emerging-threats-rule-generator
# Newest v3 release. Not releases/latest: v2 builds publish to the same
# repository and can hold the "latest" marker.
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=50" \
  | grep -o '"tag_name": *"v3[^"]*"' | head -n1 | cut -d'"' -f4)
echo "Installing $TAG"
curl -fL -o /tmp/etr-linux "https://github.com/$REPO/releases/download/$TAG/etr-linux-$ARCH"

# `install` writes a new file, so on SELinux hosts it gets the bin_t label
# for /usr/local/bin. Plain `mv` from /tmp keeps user_tmp_t and systemd
# fails with status=203/EXEC.
install -m 0755 -o root -g root /tmp/etr-linux /usr/local/bin/etr-linux
rm /tmp/etr-linux
command -v restorecon >/dev/null && restorecon -v /usr/local/bin/etr-linux

mkdir -p /etc/etr
chmod 0750 /etc/etr
```

To pin a version, set `TAG` to a tag from the releases page instead.

## 2. Write `/etc/etr/config.json`

The keys are the same as in the Docker setup (see the
[Configuration table](readme.md#configuration-configjson)). Two values differ
for native installs:

- `nginx_conf_file_path` must be inside `NGINX_CONF_DIR` (set in the unit
  file). Any other path is rejected before anything is downloaded.
- `nginx_container_names` is ignored. Set `nginx_service_name` instead if the
  unit is not named `nginx`.

```json
{
  "local_whitelist": [],
  "remote_whitelists": [],
  "local_blocklist": [],
  "remote_blocklists": [
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  ],
  "nginx_conf_file_path": "/etc/nginx/conf.d/blocklist.conf"
}
```

```bash
chmod 0640 /etc/etr/config.json
```

Optional settings go in `/etc/etr/etr.env`, one `KEY=value` per line:
`INSTANCE_NAME`, `ETR_AT_HOUR`, `ETR_JITTER_MINUTES`,
`BLOCKLIST_FAILURE_THRESHOLD`, notifier credentials (see
[Environment Variables](readme.md#environment-variables)), and
`HTTPS_PROXY` / `NO_PROXY` if the server reaches the internet through a proxy.
This file holds secrets, so restrict it:

```bash
touch /etc/etr/etr.env && chmod 0600 /etc/etr/etr.env
```

ETR only makes outbound HTTPS requests to the list URLs. It opens no ports, so
no firewall (ufw/firewalld) changes are needed.

---

## 3a. Ubuntu with ServerPilot

ServerPilot runs its own nginx as the `nginx-sp` service, with configuration
under `/etc/nginx-sp/`. nginx only allows the generated `geo` block at `http`
level. ServerPilot's `http.d/` directory is included at that level.
`vhosts.d/APP.d/*.conf` is included **inside** each app's `server` block, so
the blocklist must not go there.

In `/etc/etr/config.json`:

```json
  "nginx_conf_file_path": "/etc/nginx-sp/http.d/etr-blocklist.conf",
  "nginx_service_name": "nginx-sp"
```

Install the unit:

```bash
curl -fL -o /etc/systemd/system/etr.service \
  "https://raw.githubusercontent.com/$REPO/master/deploy/systemd/etr-serverpilot.service"
systemctl daemon-reload
systemctl enable --now etr
```

The unit is installed as `etr.service` on every platform, so the commands
below are the same everywhere.

For each app that should be protected, put the enforcement snippet from §4 in
`/etc/nginx-sp/vhosts.d/APP.d/etr-block.conf` (`APP` is the real app name),
and put the `http`-level logging file in `/etc/nginx-sp/http.d/00-etr-logging.conf`.
Then run `nginx-sp -t && service nginx-sp restart`, which is
[ServerPilot's documented apply command](https://serverpilot.io/docs/guides/nginx/customize/).
ETR uses `systemctl reload-or-restart nginx-sp`, which restarts nginx-sp the
same way if its unit has no reload action. Expect a brief interruption at each
daily update. To confirm placement, run
`nginx-sp -T | grep -n 'etr-'`: `etr-blocklist.conf` and `00-etr-logging.conf`
must appear outside any `server {` block.

## 3b. Ubuntu with distro or nginx.org nginx

Both packages include `/etc/nginx/conf.d/*.conf` at `http` level, so the
default `nginx_conf_file_path` (`/etc/nginx/conf.d/blocklist.conf`) works
unchanged.

```bash
curl -fL -o /etc/systemd/system/etr.service \
  "https://raw.githubusercontent.com/$REPO/master/deploy/systemd/etr.service"
systemctl daemon-reload
systemctl enable --now etr
```

Then put the `http`-level logging file from §4 in
`/etc/nginx/conf.d/00-etr-logging.conf`, and add the enforcement snippet to each
`server {}` that should enforce it: files in `/etc/nginx/sites-enabled/`
(distro package) or `/etc/nginx/conf.d/` (nginx.org package).

## 3c. RHEL 8 / 9 / 10 (and Rocky, Alma, Oracle)

Install nginx if needed. On RHEL 8 and 9 it ships as a module, and newer
streams are available:

```bash
dnf module list nginx            # RHEL 8/9: pick a stream, e.g.
dnf module enable -y nginx:1.24  # (skip on RHEL 10 — not modular)
dnf install -y nginx
systemctl enable --now nginx
```

RHEL's `nginx.conf` includes `/etc/nginx/conf.d/*.conf` at `http` level, so
the default `nginx_conf_file_path` works. Install the generic unit as in 3b.

Put the `http`-level logging file from §4 in `/etc/nginx/conf.d/00-etr-logging.conf`.
On RHEL 8 and 9 the stock server block is inside `/etc/nginx/nginx.conf`
itself. Add the enforcement snippet there or in your own `conf.d/*.conf`
server files.

**SELinux** (enforcing by default):

- The binary must be labeled `bin_t`. The `install` and `restorecon` steps in
  §1 do this. Check with `ls -Z /usr/local/bin/etr-linux`.
- New files in `/etc/nginx/conf.d/` inherit `httpd_config_t`, which nginx can
  read. If nginx logs `Permission denied` on `blocklist.conf`, run
  `restorecon -Rv /etc/nginx/conf.d`.
- To diagnose a denial: `ausearch -m avc -ts recent`.

**FIPS mode:** the binary is a standard Go build and does not use the system
OpenSSL. If your hosts must use only FIPS-validated crypto, check that with
whoever owns the compliance requirement before deploying.

---

## 4. Enforcement and block logging

Block logs use the Aetos ETR JSON format, the same fields the Docker ETR nginx
writes in production. Only requests ETR blocked are logged. `request_id` is
nginx's own per-request `$request_id`, not the client-controllable
`X-TD-Request-ID` header used behind Traefik. It keeps two identical blocks in
the same second from being merged into one event in Aetos.

**`http` level** (`00-etr-logging.conf`):

```nginx
map $http_user_agent $blocked_ua {
    default  "";
    ""       "empty-ua";
}

map "$blocked_ua$blocked_source" $etr_blocked {
    ""       0;
    default  1;
}

log_format etr_block escape=json
    '{"ip":"$remote_addr",'
     '"time":"$time_iso8601",'
     '"method":"$request_method",'
     '"url":"$scheme://$host$request_uri",'
     '"status":$status,'
     '"blocked_source":"$blocked_source",'
     '"blocked_ua":"$blocked_ua",'
     '"user_agent":"$http_user_agent",'
     '"request_id":"$request_id"}';
```

**Each enforcing `server {}`** (or `vhosts.d/APP.d/etr-block.conf` on ServerPilot):

```nginx
access_log /var/log/nginx/etr-block.log etr_block if=$etr_blocked;

if ($blocked_ua) {
    return 403;
}
if ($blocked_source) {
    return 403;
}
```

On ServerPilot, log to `/var/log/aetos-nginx/etr-block.log` instead, next to
the Aetos sender's app logs and covered by its logrotate rule. If the Aetos
sender isn't installed yet, create the directory first
(`install -d -m 0750 /var/log/aetos-nginx`), or `nginx-sp -t` fails. To allow
empty User-Agent requests, remove the `$blocked_ua` check *and* change the
`$etr_blocked` map key to `"$blocked_source"`. Otherwise allowed requests are
logged as blocks.

To send these blocks to Aetos, run (or rerun) the Aetos native sender
installer on the host: `setup-serverpilot-sender.sh` on ServerPilot, or
`setup-el8-nginx-sender.sh` on RHEL/Alma/Rocky 8. It detects ETR and tails this
log as an `etr` source, so Aetos records the lines as ETR WAF blocks; pass
`--etr on` to force it. Both distros' nginx logrotate configs already match
`/var/log/nginx/*.log`. Ubuntu with stock nginx and RHEL 9/10 have no Aetos
sender installer yet.

## 5. Verify

```bash
systemctl status etr
journalctl -u etr -f
```

Because no blocklist exists yet, the first start runs an update right away.
Expect one `GET` line per list, then a summary:

```
GET https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -> 200 OK, 30199 bytes in 113ms
Blocklist source https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt: 1786 entries
Collected 0 unique whitelist and 12143 unique blocklist entries (3/3 remote blocklists fetched)
Wrote 12143 entries to /etc/nginx/conf.d/blocklist.conf: ...
systemctl reload-or-restart nginx: OK
Next scheduled update at 2026-11-07 03:41:12 EST (in 16h12m)
```

To force an update now, run `systemctl restart etr`. This uses the unit's
environment. Running `etr-linux --force` from a shell does not read the unit
file, so you must pass the same variables yourself, e.g.
`NGINX_CONF_DIR=/etc/nginx-sp/http.d etr-linux --force` on ServerPilot.

### Behind a load balancer or CDN

nginx matches the blocklist against `$remote_addr`. If the server sits behind
a proxy, that is the proxy's IP, not the client's, and nothing will match.
Restore the real client IP at `http` level with the trusted proxy ranges:

```nginx
real_ip_header      X-Forwarded-For;
real_ip_recursive   on;
set_real_ip_from    10.0.0.0/8;   # your LB / CDN ranges only
```

See [Real IP trust](readme.md#real-ip-trust) for why `real_ip_recursive on`
matters.

---

## 6. Automatic updates (recommended)

`etr-update.timer` checks once a day, at a random time per host. It installs
the newest signed `v3.MINOR.PATCH` release and nothing else: timestamped
`master` builds and v2 releases are ignored.

```bash
for unit in etr-update.service etr-update.timer; do
  curl -fL -o /etc/systemd/system/$unit \
    "https://raw.githubusercontent.com/$REPO/master/deploy/systemd/$unit"
done
systemctl daemon-reload
systemctl enable --now etr-update.timer
```

Each update:

1. checks the release manifest's Ed25519 signature against the keys compiled
   into the running binary, and refuses unsigned or re-signed releases;
2. never installs an older version than the one running;
3. waits until the release is `ETR_UPDATE_DELAY_HOURS` old (default 72), so a
   bad release can be pulled before hosts install it;
4. checks the binary's SHA-256 against the signed manifest, and checks that it
   runs and reports the expected version;
5. swaps the binary in atomically, keeps the old one as
   `/usr/local/bin/etr-linux.prev`, restarts `etr`, and rolls back if it does
   not stay up.

Settings, in `/etc/etr/etr.env`:

| Variable | Default | Effect |
|---|---|---|
| `ETR_AUTO_UPDATE` | `true` | `false` turns updates off |
| `ETR_UPDATE_PIN` | — | Install exactly this tag (e.g. `v3.2.0`), including a downgrade. Skips the waiting period. |
| `ETR_UPDATE_DELAY_HOURS` | `72` | Minimum release age before install (0–720) |
| `ETR_SERVICE` | `etr` | Unit to restart; `none` to skip the restart |

The daemon itself still has no write access to `/usr/local/bin`; only the
short-lived update unit does. Check with `journalctl -u etr-update`, or run an
update now with `systemctl start etr-update`.

Binaries from before self-update was added don't have the `--self-update` flag.
Install a signed `v3.x.y` release by hand once (below); updates are automatic
from then on.

## Manual upgrade

```bash
# Set REPO, ARCH and TAG as in §1, then:
curl -fL -o /tmp/etr-linux "https://github.com/$REPO/releases/download/$TAG/etr-linux-$ARCH"
install -m 0755 -o root -g root /tmp/etr-linux /usr/local/bin/etr-linux && rm /tmp/etr-linux
command -v restorecon >/dev/null && restorecon -v /usr/local/bin/etr-linux
systemctl restart etr
```

## Uninstall

```bash
systemctl disable --now etr etr-update.timer
rm /etc/systemd/system/etr.service /etc/systemd/system/etr-update.{service,timer} \
   /usr/local/bin/etr-linux /usr/local/bin/etr-linux.prev
systemctl daemon-reload
```

Remove the enforcement snippets and `00-etr-logging.conf` before removing
`blocklist.conf`, otherwise nginx fails with `unknown "blocked_source" variable`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `status=203/EXEC` | SELinux label on the binary. Run `restorecon -v /usr/local/bin/etr-linux`. |
| `status=226/NAMESPACE` | A path in the unit's `ReadWritePaths=` doesn't exist. Create `/etc/etr`, or check you installed the right unit for your nginx. |
| `nginx_conf_file_path ... is outside allowed directory` | The path in `config.json` must be inside the unit's `NGINX_CONF_DIR`. |
| `"geo" directive is not allowed here` | The blocklist file is included inside a `server` block. Move it to an `http`-level include (§3a for ServerPilot: `http.d/`). |
| `nginx binary "nginx" not found` | Set `nginx_service_name` (e.g. `nginx-sp`) or `NGINX_BIN` in `etr.env`. |
| `0/N remote blocklists fetched` or download timeouts | Outbound HTTPS is blocked. Set `HTTPS_PROXY` in `etr.env` or allow egress to the list hosts. |
| `Warning: ignoring unknown config key` | A key in `config.json` is misspelled, so that setting is not applied. |
| `no release signing keys are compiled into this binary` | This build predates the signing key. Install a signed `v3.x.y` release by hand once. |
| `manifest signature does not match any trusted release key` | The release was not signed by a trusted key. Do not install it manually; report it. |
| `flag provided but not defined: -self-update` | The binary predates self-update. Install a signed release by hand once. |

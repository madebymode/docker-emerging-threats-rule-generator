# Native Install (no Docker)

The native build runs ETR directly on an nginx host under systemd. It is split
so that nothing which touches the network, or updates itself, runs as root:

| Part | Runs as | Can write | Job |
|---|---|---|---|
| `etr.service` (`/opt/etr/bin/etr-linux`) | `etr` | `/var/lib/etr` | Downloads the lists on a schedule (default 03:00 local, up to 60 min jitter) and stages `/var/lib/etr/blocklist.conf` |
| `etr-apply.path` → `etr-apply.service` (`/usr/local/sbin/etr-apply`) | root | the nginx include file, `/var/lib/etr-apply` | Rejects the staged file unless every line is an `<ip-or-cidr> <label>;` entry in one `geo` block, then installs it, runs `nginx -t`, reloads nginx and restores the previous file on failure |
| `etr-update.timer` → `etr-update.service` | `etr` | `/opt/etr/bin` | Installs signed `v3.X.Y` releases of the daemon. Never touches `etr-apply` |

So a compromised daemon, or a malicious release, can at most change which IPs
are blocked: it cannot write nginx configuration, run anything as root, or
block the whole internet (`etr-apply` refuses prefixes broader than /8 for
IPv4 and /16 for IPv6).

Each platform's mandatory access control adds a second layer:

| Platform | MAC | Policy |
|---|---|---|
| RHEL 8 / 9 / 10, Rocky, AlmaLinux, Oracle Linux | SELinux (enforcing by default) | `etr` module: domains `etr_t`, `etr_update_t`, `etr_apply_t` ([`deploy/selinux`](deploy/selinux)) |
| Ubuntu 20.04 / 22.04 / 24.04 / 26.04, incl. ServerPilot | AppArmor | profiles `etr-daemon`, `etr-update`, `etr-apply` ([`deploy/apparmor`](deploy/apparmor)) |

The policy is what keeps the daemon from replacing its own binary: it and the
updater run as the same user, but only the updater's domain/profile may write
`/opt/etr/bin`. `nginx -t` runs in nginx's own domain (`httpd_t`) or a child
profile, so `etr-apply` never reads TLS keys itself.

---

## 1. Install or upgrade

As root, on a host where nginx is already installed and running:

```bash
REPO=madebymode/docker-emerging-threats-rule-generator
curl -fsSL -o /tmp/etr-install.sh "https://raw.githubusercontent.com/$REPO/master/deploy/install.sh"
less /tmp/etr-install.sh          # read it: it runs as root
bash /tmp/etr-install.sh          # or: --tag v3.X.Y, --nginx serverpilot, --no-auto-update
```

`install.sh`:

1. downloads the newest signed `v3.X.Y` release and checks `manifest.json`
   against `release-signing.pub` (OpenSSL 3; on OpenSSL 1.1, i.e. RHEL 8 and
   Ubuntu 20.04, it checks SHA-256 only and tells you how to verify provenance
   with `gh attestation verify`), then every file's SHA-256;
2. creates the `etr` system user, `/opt/etr/bin` (owned by `etr`),
   `/usr/local/sbin/etr-apply` (root), `/etc/etr` and `/var/lib/etr`;
3. writes `/etc/etr/config.json` with the default lists if there is none, and
   `/etc/etr/apply.env` for your nginx (ServerPilot is detected from
   `nginx-sp.service`);
4. installs the SELinux module on RHEL or the AppArmor profiles on Ubuntu. It
   stops if that platform's MAC is disabled; pass `--no-mac` to install
   without it;
5. installs and starts the units. The first update runs immediately.

Rerunning it upgrades in place and keeps `config.json`, `etr.env` and
`apply.env`.

### Upgrading from the root daemon

Hosts installed before the split run `/usr/local/bin/etr-linux` as root and
write nginx config directly. `install.sh` migrates them: it stops the old
daemon and removes its binary, changes `nginx_conf_file_path` to
`/var/lib/etr/blocklist.conf`, and keeps the old path as the live include in
`apply.env`, so nginx configuration does not change. Self-update cannot do
this migration, because the old daemon's update unit runs as root; run
`install.sh` once by hand on each host.

## 2. Configuration

`/etc/etr/config.json` (root:etr, 0640) takes the same keys as the Docker
setup (see the [Configuration table](readme.md#configuration-configjson)),
except:

- `nginx_conf_file_path` must be `/var/lib/etr/blocklist.conf`: the daemon
  can write nowhere else.
- `nginx_container_names` and `nginx_service_name` are ignored; nginx is set
  in `apply.env`.

`/etc/etr/apply.env` (root, 0644) tells `etr-apply` where nginx is:

| Variable | nginx / nginx.org / RHEL | ServerPilot |
|---|---|---|
| `ETR_LIVE_FILE` | `/etc/nginx/conf.d/blocklist.conf` | `/etc/nginx-sp/http.d/etr-blocklist.conf` |
| `NGINX_BIN` | `nginx` | `nginx-sp` |
| `NGINX_SERVICE` | `nginx` | `nginx-sp` |

`ETR_LIVE_FILE` must be included at `http` level, because nginx allows `geo`
only there. ServerPilot's `http.d/` is; its `vhosts.d/APP.d/` is included
inside `server` blocks and is not. `etr-apply` may write only
`/etc/nginx/conf.d` and `/etc/nginx-sp/http.d` (systemd `ReadWritePaths=`, the
AppArmor profile and the SELinux label all say so). For another directory,
add it in a drop-in (`systemctl edit etr-apply.service`) and, on Ubuntu, in
`/etc/apparmor.d/local/etr-apply`.

Optional daemon settings go in `/etc/etr/etr.env` (root, 0600; systemd reads
it before dropping privileges): `INSTANCE_NAME`, `ETR_AT_HOUR`,
`ETR_JITTER_MINUTES`, `BLOCKLIST_FAILURE_THRESHOLD`, `ETR_APPLY_TIMEOUT`
(seconds to wait for `etr-apply`, default 120), notifier credentials (see
[Environment Variables](readme.md#environment-variables)), and `HTTPS_PROXY` /
`NO_PROXY`.

ETR makes only outbound HTTPS requests (and SMTP, if configured). It opens no
ports. On RHEL, SELinux allows HTTP/HTTPS, proxy and SMTP ports; for a webhook
or proxy on another port, run `setsebool -P etr_connect_any on`.

## 3. nginx placement

- **Ubuntu (distro or nginx.org nginx) and RHEL:** `/etc/nginx/conf.d/*.conf`
  is included at `http` level, so the default `ETR_LIVE_FILE` works. Add the
  enforcement snippet from §4 to each `server {}` that should block: files in
  `/etc/nginx/sites-enabled/` (Ubuntu distro package), `/etc/nginx/conf.d/`
  (nginx.org), or `/etc/nginx/nginx.conf` itself (RHEL 8/9 stock server).
  On RHEL 8/9 nginx is a module stream: `dnf module enable -y nginx:1.24 &&
  dnf install -y nginx` (RHEL 10 is not modular).
- **ServerPilot:** put the enforcement snippet in
  `/etc/nginx-sp/vhosts.d/APP.d/etr-block.conf` for each app, and the logging
  file in `/etc/nginx-sp/http.d/00-etr-logging.conf`. Then run
  `nginx-sp -t && service nginx-sp restart`
  ([ServerPilot's documented apply command](https://serverpilot.io/docs/guides/nginx/customize/)).
  nginx-sp has no reload action, so each blocklist change restarts it
  briefly. Check placement with `nginx-sp -T | grep -n 'etr-'`: both ETR files
  must appear outside any `server {` block.

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
systemctl status etr etr-apply.path
journalctl -u etr -u etr-apply -f
```

The first start builds the blocklist right away:

```
etr[...]:       Wrote 12143 entries to /var/lib/etr/blocklist.conf: ...
etr-apply[...]: installed 12143 entries into /etc/nginx/conf.d/blocklist.conf and reloaded nginx
etr[...]:       etr-apply installed the blocklist (sha256 58942532aee8)
etr[...]:       Next scheduled update at 2026-11-07 03:41:12 EST (in 16h12m)
```

Run an update now with `systemctl restart etr`. For a one-off run from a
shell, run it as `etr`, never as root (the binary directory is writable by
`etr`, and the daemon refuses to start as root):
`sudo -u etr /opt/etr/bin/etr-linux --force`.

To confirm confinement:

```bash
ps -eo user,label,args | grep etr-linux   # RHEL: etr  system_u:system_r:etr_t:s0
cat /proc/$(systemctl show -p MainPID --value etr)/attr/current   # Ubuntu: etr-daemon (enforce)
```

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

## 6. Automatic updates

`install.sh` enables `etr-update.timer` unless you pass `--no-auto-update`.
It checks once a day at a random time per host and installs the newest signed
`v3.MINOR.PATCH` release; timestamped `master` builds and v2 releases are
ignored. Each update:

1. checks the release manifest's Ed25519 signature against the keys compiled
   into the running binary, and refuses unsigned or re-signed releases;
2. never installs an older version than the one running;
3. waits until the release is `ETR_UPDATE_DELAY_HOURS` old (default 72), so a
   bad release can be pulled before hosts install it;
4. checks the binary's SHA-256 against the signed manifest, and that it runs
   and reports the expected version;
5. swaps it in atomically (the old one stays as
   `/opt/etr/bin/etr-linux.prev`) and sends the daemon SIGHUP. The daemon
   re-executes the new binary in place, keeping its PID. If it does not come
   back up on the new binary, the update rolls back.

The updater runs as `etr`, so it cannot restart units and never replaces
`etr-apply`. Updates to `etr-apply`, the units or the policies arrive by
rerunning `install.sh`; release notes say when that is needed.

| Variable (`etr.env`) | Default | Effect |
|---|---|---|
| `ETR_AUTO_UPDATE` | `true` | `false` turns updates off |
| `ETR_UPDATE_PIN` | — | Install exactly this tag (e.g. `v3.2.0`), including a downgrade. Skips the waiting period. |
| `ETR_UPDATE_DELAY_HOURS` | `72` | Minimum release age before install (0–720) |

Check with `journalctl -u etr-update`, or update now with
`systemctl start etr-update`.

## Uninstall

```bash
systemctl disable --now etr etr-apply.path etr-update.timer
rm /etc/systemd/system/etr{,-update,-apply}.service /etc/systemd/system/etr-update.timer \
   /etc/systemd/system/etr-apply.path /usr/local/sbin/etr-apply
rm -r /opt/etr /var/lib/etr /var/lib/etr-apply
systemctl daemon-reload
semodule -r etr 2>/dev/null                        # RHEL
for p in etr-daemon etr-update etr-apply; do       # Ubuntu
  apparmor_parser -R /etc/apparmor.d/$p 2>/dev/null; rm -f /etc/apparmor.d/$p
done
userdel etr
```

Remove the enforcement snippets and `00-etr-logging.conf` before removing the
live include, otherwise nginx fails with `unknown "blocked_source" variable`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `etr-apply did not report on the new blocklist within 2m0s` | `etr-apply.path` is not running (`systemctl enable --now etr-apply.path`), or `etr-apply` failed before writing a result: `journalctl -u etr-apply`. |
| `etr-apply rejected the blocklist: line N: unexpected content` | The staged file is not plain generator output. The live include was not touched. If you did not edit `/var/lib/etr/blocklist.conf` by hand, treat it as a compromise of the daemon. |
| `prefix /N is broader than /8` (or `/16`) | A list contains a huge range. Remove it from the list, or put it in `local_whitelist`. |
| `nginx -t rejected the blocklist` / `"geo" directive is not allowed here` | `ETR_LIVE_FILE` is included inside a `server` block. Use an `http`-level include (§2). |
| `nginx_conf_file_path ... is outside allowed directory "/var/lib/etr"` | A `config.json` from before the split. Set it to `/var/lib/etr/blocklist.conf`, or rerun `install.sh`. |
| `refusing to run as root` | Run the binary as `etr` (`sudo -u etr ...`) or through `systemctl`. |
| `status=203/EXEC` on RHEL | Labels. `restorecon -RFv /opt/etr /usr/local/sbin/etr-apply`. |
| SELinux denial (`ausearch -m avc -ts recent`) or AppArmor denial (`journalctl -k \| grep DENIED`) | Report it with the log line. A local workaround for AppArmor goes in `/etc/apparmor.d/local/<profile>`. |
| `0/N remote blocklists fetched` | Outbound HTTPS is blocked. Set `HTTPS_PROXY` in `etr.env`; on RHEL with a proxy on an unusual port, `setsebool -P etr_connect_any on`. |
| `Warning: ignoring unknown config key` | A key in `config.json` is misspelled, so that setting is not applied. |
| `manifest signature does not match` | The release was not signed by a trusted key. Do not install it; report it. |

**FIPS mode:** the binaries are standard Go builds and do not use the system
OpenSSL. If hosts must use only FIPS-validated crypto, check with whoever owns
that requirement before deploying.

## Testing a change

`scripts/check-policies.sh` builds and checks the policies in containers.
`scripts/vm-check.sh` installs everything on a disposable host and runs the
end-to-end checks (first update, hostile staged file, symlink, re-exec,
privileges, and zero SELinux/AppArmor denials). Run it on a RHEL VM and an
Ubuntu VM separately: each enforces only its own MAC.

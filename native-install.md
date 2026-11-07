# Native Install (no Docker)

[Documentation index](readme.md) · [Configuration reference](docs/configuration.md)

Jump to: [install/upgrade](#1-install-or-upgrade) · [configuration](#2-configuration) ·
[nginx placement](#3-nginx-placement) · [enforcement/logging](#4-enforcement-and-block-logging) ·
[verification](#5-verify) · [software checks](#6-software-release-checks-and-opt-in-updates) ·
[troubleshooting](#troubleshooting)

The native build runs ETR directly on an nginx host under systemd. It is split
so that downloaded generator/updater code runs as the unprivileged `etr` user.
Nginx application is separately controlled by the root operator:

| Part | Runs as | Can write | Job |
|---|---|---|---|
| `etr.service` (`/opt/etr/bin/etr-linux`) | `etr` | `/var/lib/etr` | Downloads the lists on a schedule (default 03:00 local, up to 60 min jitter) and stages `/var/lib/etr/blocklist.conf` |
| `etr-apply.path` → `etr-apply.service` (`/usr/local/sbin/etr-apply`) | root | the nginx include file, `/var/lib/etr-apply` | Rejects the staged file unless every line is an `<ip-or-cidr> <label>;` entry in one `geo` block, then installs it, runs `nginx -t`, reloads nginx and restores the previous file on failure |
| `etr-check-update.timer` → `etr-check-update.service` | `etr` | Notification state in `/var/lib/etr` | Checks signed release metadata daily; logs availability and optionally notifies. Never installs software |
| `etr-update.timer` → `etr-update.service` (opt-in) | `etr` | `/opt/etr/bin` | Installs signed `v3.X.Y` releases of the daemon. Never touches `etr-apply` |

The updater cannot replace the root apply helper, its systemd unit, or root
configuration. The helper accepts data in a strict IP/CIDR-and-label grammar,
not commands or arbitrary nginx directives, and rejects individual prefixes
broader than /8 for IPv4 or /16 for IPv6. Malicious data or a compromised
updater can still disrupt blocking decisions; privilege separation reduces
exposure rather than guaranteeing the absence of vulnerabilities. Root must
never execute binaries or scripts from `/opt/etr/bin`, which `etr` can write,
or include the staged file directly in nginx configuration.

Each platform's mandatory access control adds a second layer:

| Platform | MAC | Policy |
|---|---|---|
| RHEL 8 / 9 / 10, Rocky, AlmaLinux, Oracle Linux | SELinux (enforcing by default) | `etr` module: domains `etr_t`, `etr_update_t`, `etr_apply_t` ([`deploy/selinux`](deploy/selinux)) |
| Ubuntu 20.04 / 22.04 / 24.04 / 26.04, incl. ServerPilot | AppArmor | profiles `etr-daemon`, `etr-update` ([`deploy/apparmor`](deploy/apparmor)) |

The policy is what keeps the daemon from replacing its own binary: it and the
updater run as the same user, but only the updater's domain/profile may write
`/opt/etr/bin`. On Ubuntu, the root apply helper has no custom AppArmor
profile. It uses systemd filesystem restrictions, a capability bound (including
`CAP_NET_BIND_SERVICE` for nginx's listener tests), a private temporary
directory, and device access controls. The helper can read the host's nginx
configuration and TLS keys. Its strict staged-file validation and rollback
remain in place. On RHEL, the existing SELinux policy still runs `nginx -t`
in nginx's own domain (`httpd_t`). The helper omits seccomp settings that would
implicitly enable `no_new_privs` and prevent that SELinux transition; the
daemon and updater retain their existing hardening.

---

## 1. Install or upgrade

As root (nginx is required for `systemd` and `cron` modes):

```bash
REPO=madebymode/docker-emerging-threats-rule-generator
curl -fsSL -o /tmp/etr-install.sh "https://raw.githubusercontent.com/$REPO/master/deploy/install.sh"
less /tmp/etr-install.sh          # read it: it runs as root
bash /tmp/etr-install.sh          # check-only software updates; optional: --tag v3.X.Y, --nginx serverpilot
```

### Choose who applies the blocklist

| Installer option | Unprivileged generator | Root integration |
|---|---|---|
| `--apply-mode systemd` (new-install default) | Stages the list and waits for the root helper's result | Installs the fixed helper and a systemd path watcher that applies changes automatically |
| `--apply-mode cron` | Stages the list without waiting for root | Installs the fixed helper/unit; no watcher or cron job. You schedule root application yourself |
| `--apply-mode generator` | Stages the list without waiting for root | No root helper, apply unit, watcher, or cron job is installed; nginx is not required |

Every mode installs the generator, a daily release checker, and a disabled
self-update unit/timer. Software installation requires explicit `--auto-update`.
`--no-auto-update` revokes that choice; `--no-update-check` disables release
checks too. Threat-feed refreshes remain automatic in all modes. The bootstrap
installer still needs root to create the system user, ownership, and units;
normal generation and release checking never run as root.

For an operator-owned root cron schedule, install:

```bash
bash /tmp/etr-install.sh --apply-mode cron --nginx serverpilot --no-auto-update
```

Then create `/etc/cron.d/etr-apply` yourself, owned by root and mode `0644`:

```cron
SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * root /usr/bin/systemctl start etr-apply.service
```

The cron job starts a root-owned systemd unit, which runs the separately
installed `/usr/local/sbin/etr-apply`. It validates the newest staged data,
installs it atomically, tests nginx, and reloads/restarts nginx with rollback
on failure. systemd serializes overlapping starts, and identical lists skip
the nginx restart. This is intentionally an apply-and-reload job: reloading
nginx alone does not install the staged list. Inspect errors with
`journalctl -u etr-apply`; in cron mode the generator does not wait for or
report root apply failures. Until cron succeeds, nginx keeps its previous
live list. For the first install, run `systemctl start etr-apply.service`
after the generator has staged a list and before using snippets that refer
to `$blocked_source`.

For generation with no root helper installed:

```bash
bash /tmp/etr-install.sh --apply-mode generator --no-auto-update
```

Output stays at `/var/lib/etr/blocklist.conf`, outside nginx's configuration.
A separate, reviewed root workflow must validate it, copy it into a root-owned
live include, run `nginx -t`, and reload/restart with rollback. Do not source
`etr`-writable files or execute the downloadable daemon as root. Switching
to `--apply-mode cron` later installs the fixed validator for that workflow.

The selected mode is stored in root-owned `/etc/etr/apply-mode.env` and loaded
after `etr.env`. Reruns keep it unless `--apply-mode` explicitly changes it.
Moving to cron/generator disables and retires the automatic root watcher;
generator mode also backs up and retires any installed helper/unit. Existing
live configuration is preserved. Operator-owned cron jobs are never edited:
remove or adjust your cron job when changing modes. Switching back to
`--apply-mode systemd` reinstalls the helper and watcher. The mode controls
normal generator behavior; the actual privilege boundary remains filesystem
ownership, service permissions and the fixed validator.

`install.sh`:

1. downloads the newest signed `v3.X.Y` release and checks `manifest.json`
   against `release-signing.pub` using OpenSSL with Ed25519 `-rawin` support,
   then every file's SHA-256. It refuses an unverified download. Hosts with
   older OpenSSL need a supported OpenSSL installation before downloading
   releases with this installer;
2. creates the `etr` system user, `/opt/etr/bin` (owned by `etr`),
   `/etc/etr` and `/var/lib/etr`, plus `/usr/local/sbin/etr-apply` (root)
   in `systemd` and `cron` modes;
3. writes `/etc/etr/config.json` with the default lists if there is none, and
   `/etc/etr/apply.env` for your nginx (ServerPilot is detected from
   `nginx-sp.service`);
4. installs the SELinux module on RHEL or the daemon and updater AppArmor
   profiles on Ubuntu. It stops if that platform's MAC is disabled; pass
   `--no-mac` to install without it;
5. installs the units for the selected mode and restarts the daemon. Only
   `systemd` mode starts the root watcher and applies an existing staged list.
   On a new install, generation runs immediately in every mode.

Rerunning it upgrades in place and keeps `config.json`, `etr.env` and
`apply.env`. Existing services are stopped before replacing binaries and
restarted with the new units; nginx is restarted only if applying a changed
blocklist requires it.

### Upgrading an existing v3 install

Rerun `install.sh` using a signed release that includes this migration. Merely
fetching a newer bootstrap installer does not change the units inside an older
signed release: the installer rejects bundles that still select the retired
apply-helper AppArmor profile, before stopping services or changing files.
Self-update replaces only the daemon and cannot perform this migration.

The installer unloads `etr-apply` and its child profiles from the kernel and
moves `/etc/apparmor.d/etr-apply` and `/etc/apparmor.d/local/etr-apply` into a
root-only directory under `/etc/etr/migration-backups/apply.*`. It also backs
up and retires these troubleshooting drop-ins from `etr-apply.service.d`:

- `profile-transitions.conf`
- `bind-ports.conf`

Other drop-ins, configuration, staged lists and the live nginx include are
preserved. Review any other custom override that explicitly selects
`AppArmorProfile=etr-apply`; it must be removed before running the new unit.
Retirement also runs with `--no-mac`, since the old profile's executable-path
attachment would otherwise continue to confine the helper. Rerunning the
installer after migration is safe and does not create another backup unless
retired files have reappeared.

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
setup (see the [Configuration table](docs/configuration.md#json-fields)),
except:

- `nginx_conf_file_path` must be `/var/lib/etr/blocklist.conf`: the daemon
  stages generated output within that directory. In `cron` and `generator` modes, staging succeeds
  without waiting for a root service; validation and live-file rollback happen
  in the separately scheduled root workflow.
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
inside `server` blocks and is not. Within `/etc`, systemd makes only
`/etc/nginx/conf.d` and `/etc/nginx-sp/http.d` writable for `etr-apply`.
`/var` remains writable so nginx can open logs and create runtime files.
For another live include directory under `/etc`, add `ReadWritePaths=` in a
drop-in (`systemctl edit etr-apply.service`). On RHEL, the directory also needs
the nginx configuration SELinux label.

Optional daemon settings go in `/etc/etr/etr.env` (root, 0600; systemd reads
it before dropping privileges): `INSTANCE_NAME`, `ETR_AT_HOUR`,
`ETR_JITTER_MINUTES`, `BLOCKLIST_FAILURE_THRESHOLD`, `ETR_APPLY_TIMEOUT`
(seconds to wait for `etr-apply`, default 120), notifier credentials (see
[Environment Variables](docs/configuration.md#scheduling-and-application)), and `HTTPS_PROXY` /
`NO_PROXY`.

ETR makes outbound connections for feeds, release checks, and configured
notification endpoints (HTTP(S) or SMTP). It does not listen on network ports. On RHEL, SELinux allows HTTP/HTTPS, proxy and SMTP ports; for a webhook
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

The installer connects the ETR services to journald automatically. It does
not install nginx enforcement or blocked-request logging snippets: add the
configuration below for your sites. Installing a list alone does not enforce it.

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

In `systemd` mode, the first start builds and applies the blocklist right away:

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

For a one-off generation in `cron` or `generator` mode, also pass the mode
explicitly; commands launched outside systemd do not inherit its environment
files. For example:
`sudo -u etr env ETR_APPLY_MODE=cron /opt/etr/bin/etr-linux --force`.

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

See [Real IP trust](docs/nginx.md#real-ip-trust) for why `real_ip_recursive on`
matters.

---

## 6. Software release checks and opt-in updates

By default, `etr-check-update.timer` checks daily with up to 12 hours of jitter.
The checker runs as `etr` under the daemon's confinement, with no permission to
write executable files. It downloads only the release index, manifest and
signature, verifies the manifest using embedded trusted keys, and logs the
installed version, available version, signed publication date and release URL.
It does not download binaries, re-execute the daemon, or reload nginx.

```bash
systemctl start etr-check-update.service       # check now
journalctl -u etr-check-update --no-pager
```

To send alerts through the notification channels already configured in
`/etc/etr/etr.env`, add:

```ini
ETR_UPDATE_NOTIFY=true
ETR_UPDATE_REMINDER_HOURS=168
```

Alerts are off by default. Each successfully notified channel is remembered in
`/var/lib/etr/update-notices.json`, and receives a reminder after 168 hours
(one week) by default. A changed installed or available version resets the
notice. Failed channels retry on the next check without resending successful
channels. Release checks are logged every run, even when an alert is suppressed.
If state is corrupt, fix or remove that file to resume notifications; removing
it allows another alert. State contains versions, channel names and timestamps,
not credentials. A checker service run is limited to five minutes so a stalled
notification backend cannot run indefinitely.

The checker reports the newest stable `v3.MINOR.PATCH` release regardless of an
installation pin or waiting period. Drafts, prereleases and timestamped builds
are excluded. A failed fetch or signature check fails the service and logs an
error; it never reports success or sends an availability alert for that release.

### Opt into installation

Rerun the reviewed installer with `--auto-update` to record explicit consent
and enable `etr-update.timer`. It installs the newest signed release after the
configured waiting period, verifies its digest, keeps the previous executable,
asks the daemon to re-execute, and rolls back if the daemon fails its health
check. The root helper, policies and units are updated only by the installer.

```bash
bash /tmp/etr-install.sh --auto-update
# To revoke consent while retaining release checks:
bash /tmp/etr-install.sh --no-auto-update
```

The choice is recorded in root-owned `/etc/etr/update-policy.env`, loaded after
`etr.env` by the updater service. A legacy `ETR_AUTO_UPDATE=true` in `etr.env`
cannot override it. Direct `--self-update` invocations as `etr` also require
`ETR_AUTO_UPDATE=true`; invoking the binary as root is always refused.

| Setting | Default | Effect |
|---|---|---|
| `ETR_AUTO_UPDATE` (installer-managed for the service) | `false` | Only exact `true` permits software installation |
| `ETR_UPDATE_NOTIFY` (`etr.env`) | `false` | Exact `true` sends availability notices through configured channels |
| `ETR_UPDATE_REMINDER_HOURS` (`etr.env`) | `168` | Repeat successful notices after this interval (1–8760 hours) |
| `ETR_UPDATE_PIN` (`etr.env`) | — | Install this tag, including a downgrade; skips the waiting period; does not enable installation |
| `ETR_UPDATE_DELAY_HOURS` (`etr.env`) | `72` | Minimum release age before automatic installation (0–720 hours) |

### Existing installations

Rerunning this installer converts legacy enabled update timers to check-only
unless `--auto-update` is supplied. An old enabled timer is not treated as
explicit consent. Subsequent reruns preserve the recorded opt-in while the
timer remains enabled, and respect manually disabled timers. This migration
requires a new signed deployment bundle; daemon self-update alone cannot
install the checker units or migrate the timer configuration.

To stop only release checks, use `--no-update-check` or
`systemctl disable --now etr-check-update.timer`. Reruns preserve that disabled
state. Re-enable with `systemctl enable --now etr-check-update.timer`.
These software policies do not change scheduled threat-feed refreshes.
APT/DNF packages remain planned; they are not implemented install options.

## Uninstall

```bash
systemctl disable --now etr etr-apply.path etr-update.timer etr-check-update.timer
systemctl stop etr-update.service etr-check-update.service
rm /etc/systemd/system/etr{,-update,-apply,-check-update}.service /etc/systemd/system/etr{,-check}-update.timer \
   /etc/systemd/system/etr-apply.path /usr/local/sbin/etr-apply
rm -r /opt/etr /var/lib/etr /var/lib/etr-apply
# If you created an operator-owned cron job, remove it separately.
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
| Old `etr-apply` AppArmor denials (binary execution, PID/scratch files, listeners or systemctl bus access) | Rerun `install.sh` with a release containing the apply-profile retirement migration. It removes the old helper profile and known troubleshooting drop-ins while retaining daemon/updater confinement. |
| SELinux denial (`ausearch -m avc -ts recent`) or AppArmor denial (`journalctl -k \| grep DENIED`) | Report it with the log line. A local workaround for AppArmor goes in `/etc/apparmor.d/local/<profile>`. |
| `0/N remote blocklists fetched` | Outbound HTTPS is blocked. Set `HTTPS_PROXY` in `etr.env`; on RHEL with a proxy on an unusual port, `setsebool -P etr_connect_any on`. |
| `Warning: ignoring unknown config key` | A key in `config.json` is misspelled, so that setting is not applied. |
| `manifest signature does not match` | The release was not signed by a trusted key. Do not install it; report it. |

**FIPS mode:** the binaries are standard Go builds and do not use the system
OpenSSL. If hosts must use only FIPS-validated crypto, check with whoever owns
that requirement before deploying.

## Testing a change

`bash tests/native-install.sh` exercises the installer in a disposable Ubuntu
container: fresh install, migration of the patched ServerPilot setup, repeat
installs, configuration and custom override preservation, retirement with
`--no-mac`, old root-daemon migration, unload failure, and rejection of old
deployment bundles. It uses real filesystem operations and Ubuntu's policy/unit
syntax checkers; systemd and AppArmor kernel operations are simulated. It
also tests mode persistence, migration from automatic to cron/generator,
generator installs without nginx or a root helper asset, and switching back
to automatic application.

`scripts/check-policies.sh` builds and checks the policies in containers.
`scripts/vm-check.sh` installs everything on a disposable host and runs the
end-to-end checks (first update, hostile staged file, symlink, re-exec,
privileges, and zero SELinux/AppArmor denials). Run it on a RHEL VM and an
Ubuntu VM separately: each enforces only its own MAC.

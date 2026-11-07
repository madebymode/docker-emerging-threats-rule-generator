#!/usr/bin/env bash
# Installs or upgrades native ETR on a systemd host (Ubuntu 20.04+, RHEL 8-10).
#
#   etr.service       daemon, user etr, writes only /var/lib/etr
#   etr-check-update.timer  signed release checks, user etr, no installation
#   etr-update.timer  opt-in self-update, user etr, writes only /opt/etr/bin
#   etr-apply.path    root installer: validates /var/lib/etr/blocklist.conf
#                     and installs it into nginx
#
# Usage (as root):
#   install.sh [--tag v3.X.Y] [--from DIR] [--nginx nginx|serverpilot]
#              [--apply-mode systemd|cron|generator] [--auto-update|--no-auto-update] [--no-update-check] [--no-mac]
#
#   --tag      release to install (default: newest signed v3.X.Y release)
#   --from     install binaries from DIR (etr-linux-ARCH, etr-apply-linux-ARCH,
#              optional etr-selinux-elN.pp) and unit files from this script's
#              directory, instead of downloading a release. For test VMs.
#   --nginx    nginx flavour (default: serverpilot if nginx-sp is installed)
#   --apply-mode  systemd: apply on changes (default); cron: operator schedules
#                 root apply; generator: stage lists only, no root helper
#                 (reruns keep the previously selected mode)
#   --auto-update     opt in to software installation (default: check only)
#   --no-auto-update  revoke opt-in; reruns preserve recorded choices
#   --no-update-check disable release checks; existing disabled checks stay off
#   --no-mac   do not install the SELinux module (RHEL) or AppArmor profiles
#              (Ubuntu). Without it, the platform's MAC must be enabled.
#
# Rerunning is safe: it upgrades binaries, units and policies in place and
# keeps config.json, etr.env and apply.env. Hosts on the old layout
# (/usr/local/bin/etr-linux running as root) are migrated.
set -euo pipefail

REPO=madebymode/docker-emerging-threats-rule-generator
tag="" from="" flavour="" auto_update="" mac=1 apply_mode="" update_check=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --tag) tag=$2; shift 2 ;;
    --from) from=$(cd "$2" && pwd); shift 2 ;;
    --nginx) flavour=$2; shift 2 ;;
    --apply-mode) apply_mode=$2; shift 2 ;;
    --auto-update) auto_update=1; shift ;;
    --no-auto-update) auto_update=0; shift ;;
    --no-update-check) update_check=0; shift ;;
    --no-mac) mac=0; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || die "run as root"
[[ -d /run/systemd/system ]] || die "systemd is required"
# Read the managed mode as data, never source an environment file as root.
if [[ -z $apply_mode && -f /etc/etr/apply-mode.env ]]; then
  apply_mode=$(sed -n 's/^ETR_APPLY_MODE=//p' /etc/etr/apply-mode.env)
fi
apply_mode=${apply_mode:-systemd}
case $apply_mode in
  systemd|cron|generator) ;;
  *) die "--apply-mode must be systemd, cron or generator" ;;
esac
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

# Old enabled timers were an installer default, not evidence of consent.
# Only an explicit --auto-update records opt-in under the new policy.
if [[ -z $auto_update ]]; then
  auto_update=0
  if [[ -f /etc/etr/update-policy.env ]] && grep -qx 'ETR_AUTO_UPDATE=true' /etc/etr/update-policy.env && systemctl is-enabled --quiet etr-update.timer; then
    auto_update=1
  fi
fi
if [[ -z $update_check ]]; then
  update_check=1
  if systemctl cat etr-check-update.timer >/dev/null 2>&1 && ! systemctl is-enabled --quiet etr-check-update.timer; then
    update_check=0
  fi
fi

artifacts=("etr-linux-$arch")
[[ $apply_mode == generator ]] || artifacts+=("etr-apply-linux-$arch")

# Each platform has its own mandatory access control: SELinux on RHEL and its
# rebuilds, AppArmor on Ubuntu (and Debian). Neither is used on the other.
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" rhel "*|*" centos "*|*" fedora "*) platform=rhel; el=${VERSION_ID%%.*} ;;
  *" ubuntu "*|*" debian "*) platform=ubuntu ;;
  *) die "unsupported distribution ${ID:-unknown}; ETR supports Ubuntu and RHEL 8-10" ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

if [[ -n $from ]]; then
  src=$from
  deploy=$(cd "$(dirname "$0")" && pwd)
else
  command -v curl >/dev/null || die "curl is required"
  if [[ -z $tag ]]; then
    # Not releases/latest: v2 builds share the repository and the marker.
    tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=50" \
      | grep -o '"tag_name": *"v3\.[0-9]*\.[0-9]*"' | head -n1 | cut -d'"' -f4)
    [[ -n $tag ]] || die "no signed v3.X.Y release found"
  fi
  [[ $tag =~ ^v3\.[0-9]+\.[0-9]+$ ]] || die "$tag is not a v3.X.Y release"
  log "Downloading $tag"
  base="https://github.com/$REPO/releases/download/$tag"
  src=$work
  for f in manifest.json manifest.json.sig "${artifacts[@]}" etr-deploy.tar.gz; do
    curl -fsSL -o "$work/$f" "$base/$f" || die "downloading $f from $tag failed"
  done

  # The signature check needs OpenSSL 3 (Ed25519 with -rawin). The keys are
  # fetched from the tag itself; self-update afterwards uses the keys
  # compiled into the binary.
  curl -fsSL -o "$work/release-signing.pub" \
    "https://raw.githubusercontent.com/$REPO/$tag/release-signing.pub"
  if openssl pkeyutl -help 2>&1 | grep -q -- -rawin; then
    # One file per key: pkeyutl reads only the first key in a PEM file.
    awk -v dir="$work" '/BEGIN PUBLIC KEY/{n++} n{print > (dir "/key" n ".pem")}' "$work/release-signing.pub"
    ok=0
    for key in "$work"/key*.pem; do
      [[ -f $key ]] || continue
      if openssl pkeyutl -verify -pubin -inkey "$key" -rawin \
          -in "$work/manifest.json" -sigfile "$work/manifest.json.sig" >/dev/null 2>&1; then
        ok=1; break
      fi
    done
    [[ $ok -eq 1 ]] || die "manifest signature does not match release-signing.pub; do not install this release"
    log "Manifest signature verified"
  else
    die "OpenSSL with Ed25519 -rawin support is required; refusing to install without verifying the release signature"
  fi
  grep -q "\"tag\":\"$tag\"" <(tr -d ' \n' < "$work/manifest.json") || die "manifest is not for $tag"
  for f in "${artifacts[@]}" etr-deploy.tar.gz; do
    want=$(tr -d ' \n' < "$work/manifest.json" | grep -o "\"$f\":\"[0-9a-f]*\"" | cut -d'"' -f4)
    got=$(sha256sum "$work/$f" | cut -d' ' -f1)
    [[ -n $want && $want == "$got" ]] || die "$f does not match the signed manifest"
  done
  tar -xzf "$work/etr-deploy.tar.gz" -C "$work"
  deploy=$work/deploy
fi

for f in "${artifacts[@]}"; do
  [[ -f $src/$f ]] || die "missing $src/$f"
done
for unit in etr.service etr-update.service etr-update.timer etr-check-update.service etr-check-update.timer etr-apply.service etr-apply.path; do
  [[ -f $deploy/systemd/$unit ]] || die "missing $deploy/systemd/$unit"
done
# The bootstrap installer can be newer than the signed release it downloads.
# Never retire a profile and then reinstall a unit that still selects it.
if [[ -f $deploy/apparmor/etr-apply ]] || grep -Eq '^[[:space:]]*AppArmorProfile=.*etr-apply' "$deploy/systemd/etr-apply.service"; then
  die "selected release still uses the retired etr-apply AppArmor profile; select a newer signed release with --tag"
fi

if ! grep -qx 'EnvironmentFile=-/etc/etr/apply-mode.env' "$deploy/systemd/etr.service"; then
  die "selected release does not support apply modes; select a newer signed release with --tag"
fi

if ! grep -qx 'EnvironmentFile=-/etc/etr/update-policy.env' "$deploy/systemd/etr-update.service"; then
  die "selected release does not support opt-in software updates; select a newer signed release with --tag"
fi

# ---------------------------------------------------------------------------
# nginx flavour
# ---------------------------------------------------------------------------

if [[ -z $flavour ]]; then
  if systemctl cat nginx-sp.service >/dev/null 2>&1; then flavour=serverpilot; else flavour=nginx; fi
fi
case $flavour in
  nginx) live=/etc/nginx/conf.d/blocklist.conf; nginx_bin=nginx; nginx_service=nginx ;;
  serverpilot) live=/etc/nginx-sp/http.d/etr-blocklist.conf; nginx_bin=nginx-sp; nginx_service=nginx-sp ;;
  *) die "--nginx must be nginx or serverpilot" ;;
esac
if [[ $apply_mode != generator ]]; then
  command -v "$nginx_bin" >/dev/null || die "$nginx_bin not found; install nginx first"
fi
log "apply mode: $apply_mode; nginx flavour: $flavour"

# ---------------------------------------------------------------------------
# Old layout: daemon as root in /usr/local/bin, writing nginx config itself
# ---------------------------------------------------------------------------

# Stop existing services before replacing executables, units or confinement.
# The updater must not race installation and the path watcher must not start
# another helper while its old profile is being retired.
for unit in etr-update.timer etr-update.service etr-check-update.timer etr-check-update.service etr-apply.path etr.service; do
  if systemctl cat "$unit" >/dev/null 2>&1; then
    systemctl stop "$unit" || die "could not stop $unit before upgrading"
  fi
done
if systemctl cat etr-apply.service >/dev/null 2>&1; then
  # A oneshot stays "activating" until it exits. Wait for an in-flight apply
  # to finish testing/reloading or rolling back before stopping it; killing
  # it between installation and validation could leave an untested live file.
  if [[ $(systemctl show -p ActiveState --value etr-apply.service) == activating ]]; then
    systemctl start etr-apply.service || true
  fi
  systemctl stop etr-apply.service || die "could not stop etr-apply.service before upgrading"
fi

if [[ $apply_mode != systemd ]] && systemctl cat etr-apply.path >/dev/null 2>&1; then
  systemctl disable etr-apply.path || die "could not disable the automatic apply watcher"
fi

old_live=""
if [[ -f /usr/local/bin/etr-linux ]]; then
  log "Migrating from the root daemon at /usr/local/bin/etr-linux"
  if [[ -f /etc/etr/config.json ]]; then
    old_live=$(grep -o '"nginx_conf_file_path"[^,}]*' /etc/etr/config.json | cut -d'"' -f4 || true)
  fi
  rm -f /usr/local/bin/etr-linux /usr/local/bin/etr-linux.prev
fi

# ---------------------------------------------------------------------------
# User, directories, binaries
# ---------------------------------------------------------------------------

if ! id etr >/dev/null 2>&1; then
  nologin=$(command -v nologin || echo /usr/sbin/nologin)
  useradd --system --home-dir /var/lib/etr --no-create-home --shell "$nologin" \
    --comment "ETR blocklist daemon" etr
  log "Created system user etr"
fi

install -d -m 0755 -o root -g root /opt/etr
# etr owns the binary directory so self-update needs no root. Root never
# executes anything from it; etr-apply is installed separately below.
install -d -m 0755 -o etr -g etr /opt/etr/bin
install -m 0755 -o etr -g etr "$src/etr-linux-$arch" /opt/etr/bin/etr-linux
if [[ $apply_mode != generator ]]; then
  install -m 0755 -o root -g root "$src/etr-apply-linux-$arch" /usr/local/sbin/etr-apply
fi

install -d -m 0750 -o root -g etr /etc/etr
# systemd would create this when etr first starts, but etr-apply.path must be
# watching the directory itself by then, or it misses the first blocklist.
install -d -m 0750 -o etr -g etr /var/lib/etr
if [[ ! -f /etc/etr/config.json ]]; then
  cat > /etc/etr/config.json <<'JSON'
{
  "local_whitelist": [],
  "remote_whitelists": [],
  "local_blocklist": [],
  "remote_blocklists": [
    "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  ],
  "nginx_conf_file_path": "/var/lib/etr/blocklist.conf"
}
JSON
  log "Wrote /etc/etr/config.json with the default lists"
elif ! grep -q '"nginx_conf_file_path": *"/var/lib/etr/' /etc/etr/config.json; then
  sed -i -E 's#("nginx_conf_file_path": *")[^"]*"#\1/var/lib/etr/blocklist.conf"#' /etc/etr/config.json
  grep -q '"nginx_conf_file_path": *"/var/lib/etr/blocklist.conf"' /etc/etr/config.json \
    || die "could not set nginx_conf_file_path in /etc/etr/config.json; set it to /var/lib/etr/blocklist.conf"
  log "Set nginx_conf_file_path to /var/lib/etr/blocklist.conf"
fi
chown root:etr /etc/etr/config.json
chmod 0640 /etc/etr/config.json

# systemd reads etr.env as root before dropping to etr, so it can stay 0600.
[[ -f /etc/etr/etr.env ]] || install -m 0600 -o root -g root /dev/null /etc/etr/etr.env
# Loaded after etr.env, so old RESTART_CONTAINERS settings cannot turn a
# cron/generator install back into an automatic apply-and-wait installation.
printf 'ETR_APPLY_MODE=%s\n' "$apply_mode" > /etc/etr/apply-mode.env
chown root:root /etc/etr/apply-mode.env
chmod 0644 /etc/etr/apply-mode.env
# Load after etr.env: legacy ETR_AUTO_UPDATE values cannot bypass the decision.
if [[ $auto_update == 1 ]]; then policy=true; else policy=false; fi
printf 'ETR_AUTO_UPDATE=%s\n' "$policy" > /etc/etr/update-policy.env
chown root:root /etc/etr/update-policy.env
chmod 0644 /etc/etr/update-policy.env

# The old layout set NGINX_CONF_DIR for the daemon; it now only writes /var/lib/etr.
sed -i '/^NGINX_CONF_DIR=/d;/^NGINX_SERVICE=/d;/^ETR_SERVICE=/d' /etc/etr/etr.env

if [[ ! -f /etc/etr/apply.env ]]; then
  # Keep the include path a migrated host already uses, so nginx needs no change.
  [[ -n $old_live && $old_live != /var/lib/etr/* ]] && live=$old_live
  printf 'ETR_LIVE_FILE=%s\nNGINX_BIN=%s\nNGINX_SERVICE=%s\n' "$live" "$nginx_bin" "$nginx_service" \
    > /etc/etr/apply.env
  chmod 0644 /etc/etr/apply.env
  log "Wrote /etc/etr/apply.env (blocklist include: $live)"
fi

# ---------------------------------------------------------------------------
# Retire the old apply-helper confinement, including test-box workarounds.
# This also runs with --no-mac: an old path-attached profile still confines
# etr-apply even if AppArmorProfile= is removed from the unit.
# ---------------------------------------------------------------------------

if [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]]; then
  profiles=/sys/kernel/security/apparmor/profiles
  [[ -r $profiles ]] || die "cannot inspect loaded AppArmor profiles at $profiles; refusing to leave etr-apply confined"
  if grep -q '^etr-apply ' "$profiles"; then
    command -v apparmor_parser >/dev/null || die "apparmor_parser is required to unload the retired etr-apply profile"
    # Remove by name, independently of any local edits to the old policy.
    printf 'profile etr-apply {}\n' > "$work/retired-etr-apply"
    apparmor_parser -R "$work/retired-etr-apply" || die "could not unload the retired etr-apply AppArmor profile"
    log "Unloaded the retired etr-apply AppArmor profile and its children"
  fi
fi

migration_backup=""
retired_files=(/etc/apparmor.d/etr-apply /etc/apparmor.d/local/etr-apply
  /etc/systemd/system/etr-apply.service.d/profile-transitions.conf
  /etc/systemd/system/etr-apply.service.d/bind-ports.conf)
# Changing mode also retires automatic root triggers and, for generator-only
# installs, the root helper itself. Operator-owned cron jobs are never edited.
[[ $apply_mode == systemd ]] || retired_files+=(/etc/systemd/system/etr-apply.path)
if [[ $apply_mode == generator ]]; then
  retired_files+=(/etc/systemd/system/etr-apply.service /usr/local/sbin/etr-apply)
fi
for retired in "${retired_files[@]}"; do
  [[ -e $retired || -L $retired ]] || continue
  if [[ -z $migration_backup ]]; then
    install -d -m 0700 /etc/etr/migration-backups
    migration_backup=$(mktemp -d /etc/etr/migration-backups/apply.XXXXXX)
  fi
  # Preserve original paths in the backup, including local profile additions.
  install -d -m 0700 "$migration_backup$(dirname "$retired")"
  mv "$retired" "$migration_backup$retired"
done
[[ -z $migration_backup ]] || log "Backed up retired apply confinement to $migration_backup"

# ---------------------------------------------------------------------------
# Mandatory access control
# ---------------------------------------------------------------------------

if [[ $mac -eq 0 ]]; then
  log "WARNING: --no-mac: ETR runs without its $([[ $platform == rhel ]] && echo SELinux module || echo AppArmor profiles)"
elif [[ $platform == rhel ]]; then
  command -v selinuxenabled >/dev/null && selinuxenabled \
    || die "SELinux is disabled on this host. Enable it (RHEL's default), or rerun with --no-mac"
  pp=""
  for candidate in "$src/etr-selinux-el$el.pp" "$deploy/selinux/etr-selinux-el$el.pp"; do
    [[ -f $candidate ]] && { pp=$candidate; break; }
  done
  if [[ -z $pp && -f /usr/share/selinux/devel/Makefile && -f $deploy/selinux/etr.te ]]; then
    cp "$deploy/selinux/etr."{te,if,fc} "$work/"
    make -s -C "$work" -f /usr/share/selinux/devel/Makefile etr.pp >/dev/null
    pp=$work/etr.pp
  fi
  [[ -n $pp ]] || die "no SELinux module for EL$el; install selinux-policy-devel, or rerun with --no-mac"
  semodule -i "$pp"
  log "Installed SELinux module etr ($(basename "$pp"))"
  [[ $(getenforce) == Enforcing ]] || log "WARNING: SELinux is $(getenforce); the etr module only logs denials until it is Enforcing"
else
  [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]] \
    || die "AppArmor is not enabled on this host. Enable it (Ubuntu's default), or rerun with --no-mac"
  command -v apparmor_parser >/dev/null || die "apparmor_parser not found; apt-get install apparmor"
  for p in etr-daemon etr-update; do
    install -m 0644 "$deploy/apparmor/$p" "/etc/apparmor.d/$p"
    [[ -f /etc/apparmor.d/local/$p ]] || install -D -m 0644 /dev/null "/etc/apparmor.d/local/$p"
    apparmor_parser -r "/etc/apparmor.d/$p"
  done
  log "Loaded AppArmor profiles etr-daemon, etr-update (enforce)"
fi

# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------

units=(etr.service etr-update.service etr-update.timer etr-check-update.service etr-check-update.timer)
[[ $apply_mode == generator ]] || units+=(etr-apply.service)
[[ $apply_mode != systemd ]] || units+=(etr-apply.path)
for unit in "${units[@]}"; do
  install -m 0644 "$deploy/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload

# Labels for everything above, and for the state directories once systemd
# creates them.
command -v restorecon >/dev/null && restorecon -RF /opt/etr /usr/local/sbin/etr-apply /etc/etr /var/lib/etr 2>/dev/null || true

if [[ $apply_mode == systemd ]]; then
  systemctl enable --now etr-apply.path
  # Retry any existing staged blocklist with the newly installed helper/unit.
  systemctl start etr-apply.service
fi
systemctl enable etr.service
systemctl restart etr.service
if [[ $auto_update -eq 1 ]]; then
  systemctl enable --now etr-update.timer
else
  systemctl disable --now etr-update.timer 2>/dev/null || true
fi
if [[ $update_check -eq 1 ]]; then
  systemctl enable --now etr-check-update.timer
else
  systemctl disable --now etr-check-update.timer
fi
log "Software auto-update: $policy; release checks: $update_check (journalctl -u etr-check-update)"
command -v restorecon >/dev/null && restorecon -RF /var/lib/etr-apply 2>/dev/null || true

# Never run /opt/etr/bin as root: etr can write it.
log "Installed $(runuser -u etr -- /opt/etr/bin/etr-linux --version 2>/dev/null || echo "$tag")."
if [[ $apply_mode == cron ]]; then
  cat <<'EOF'

Next: schedule root application at a cadence you control, for example in
/etc/cron.d/etr-apply (root-owned, 0644):
  */5 * * * * root /usr/bin/systemctl start etr-apply.service
No cron job has been installed. The generator stages lists without waiting
for application. Inspect failures with: journalctl -u etr-apply
EOF
elif [[ $apply_mode == generator ]]; then
  cat <<'EOF'

Next: the unprivileged generator stages /var/lib/etr/blocklist.conf only.
No root apply helper, apply unit, watcher or cron job is installed.
Use a separately reviewed root workflow to validate, install, test and reload
nginx, or rerun this installer with --apply-mode cron for the fixed validator.
Never execute /opt/etr/bin/etr-linux or any etr-owned script as root, and never
include the etr-writable staged file directly in nginx configuration.
Review any existing root cron job before switching modes; it was not edited.
EOF
else
cat <<EOF

Next:
  journalctl -u etr -u etr-apply -f     # first update runs now
  $nginx_bin -T | grep -n blocklist    # the include must sit at http level

Add the enforcement and logging snippets to nginx if this is a new install
(native-install.md, section 4).
EOF
fi

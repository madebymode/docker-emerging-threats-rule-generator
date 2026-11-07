#!/usr/bin/env bash
# Exercise the real installer in a disposable Ubuntu filesystem. systemd and
# AppArmor kernel operations are simulated; file installation/migration is real.
# Run from any host with Docker: bash tests/native-install.sh
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
if [[ ${1:-} != --container ]]; then
  exec docker run --rm -v "$repo:/src:ro" ubuntu:24.04 bash -euc '
    apt-get -qq update >/dev/null
    apt-get -qq install -y apparmor systemd shellcheck >/dev/null 2>&1
    bash /src/tests/native-install.sh --container
  '
fi
[[ -f /.dockerenv && $(id -u) -eq 0 ]] || { echo 'container-only test' >&2; exit 1; }

test_root=$(mktemp -d)
export ETR_INSTALL_TEST_ROOT=$test_root
mkdir -p "$test_root/bin" "$test_root/dist" "$test_root/deploy" /run/systemd/system
cp -R "$repo/deploy/." "$test_root/deploy/"
# Substitute only kernel virtual files, which Docker cannot provide. Every
# /etc, /opt, /usr/local and /var migration uses its actual container path.
sed -i \
  -e "s|/sys/module/apparmor/parameters/enabled|$test_root/apparmor-enabled|g" \
  -e "s|/sys/kernel/security/apparmor/profiles|$test_root/profiles|g" \
  "$test_root/deploy/install.sh"
echo Y > "$test_root/apparmor-enabled"
: > "$test_root/profiles"
: > "$test_root/commands"

# Validate shipped policy/unit syntax with real Ubuntu tools before mocking
# the kernel and service manager. Never load policy into the Docker host.
for profile in etr-daemon etr-update; do
  touch "/etc/apparmor.d/local/$profile"
  apparmor_parser --skip-kernel-load --skip-cache --skip-read-cache "$repo/deploy/apparmor/$profile"
done
cp /bin/true /usr/local/sbin/etr-apply
systemd-analyze verify "$repo/deploy/systemd/etr-apply.service"
shellcheck -S warning "$repo/deploy/install.sh" "$repo/tests/native-install.sh"

cat > "$test_root/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >> "$ETR_INSTALL_TEST_ROOT/commands"
if [[ $1 == cat ]]; then
  [[ $2 == nginx-sp.service || -f /etc/systemd/system/$2 ]]
elif [[ $1 == is-enabled ]]; then
  [[ -f $ETR_INSTALL_TEST_ROOT/enabled-${!#} ]]
elif [[ $1 == enable || $1 == disable ]]; then
  for unit in "$@"; do
    if [[ $unit == *.timer ]]; then
      if [[ $1 == enable ]]; then touch "$ETR_INSTALL_TEST_ROOT/enabled-$unit"; else rm -f "$ETR_INSTALL_TEST_ROOT/enabled-$unit"; fi
    fi
  done
elif [[ $1 == show ]]; then
  if [[ -f $ETR_INSTALL_TEST_ROOT/apply-pending ]]; then echo activating; else echo inactive; fi
elif [[ $1 == start && $2 == etr-apply.service ]]; then
  rm -f "$ETR_INSTALL_TEST_ROOT/apply-pending"
elif [[ $1 == stop && $2 == etr-apply.service ]]; then
  # Stopping an active helper without waiting could interrupt its rollback.
  [[ ! -f $ETR_INSTALL_TEST_ROOT/apply-pending ]]
fi
EOF
cat > "$test_root/bin/apparmor_parser" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'apparmor_parser %s\n' "$*" >> "$ETR_INSTALL_TEST_ROOT/commands"
if [[ $1 == -R ]]; then
  [[ ${ETR_TEST_UNLOAD_FAIL:-0} != 1 ]] || exit 1
  grep -qx 'profile etr-apply {}' "$2"
  sed -i '/^etr-apply[ /]/d' "$ETR_INSTALL_TEST_ROOT/profiles"
elif [[ $1 == -r ]]; then
  name=${2##*/}
  [[ $name == etr-daemon || $name == etr-update ]]
  if ! grep -q "^$name " "$ETR_INSTALL_TEST_ROOT/profiles"; then
    printf '%s (enforce)\n' "$name" >> "$ETR_INSTALL_TEST_ROOT/profiles"
  fi
else
  exit 1
fi
EOF
cat > "$test_root/bin/nginx-sp" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$test_root/bin/"*
export PATH="$test_root/bin:$PATH"
case $(uname -m) in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) exit 1 ;;
esac
for binary in etr-linux etr-apply-linux; do
  printf '#!/bin/sh\necho test-version\n' > "$test_root/dist/$binary-$arch"
done
run_install() {
  bash "$test_root/deploy/install.sh" --from "$test_root/dist" --no-auto-update "$@"
}
assert() { if ! "$@"; then printf 'FAIL: %s\n' "$*" >&2; exit 1; fi; }
seed_old_confinement() {
  mkdir -p /etc/apparmor.d/local /etc/systemd/system/etr-apply.service.d
  echo 'locally patched legacy profile' > /etc/apparmor.d/etr-apply
  echo 'local policy additions' > /etc/apparmor.d/local/etr-apply
  cat > /etc/systemd/system/etr-apply.service.d/profile-transitions.conf <<'EOF'
[Service]
NoNewPrivileges=no
PrivateDevices=no
ProtectKernelTunables=no
ProtectKernelModules=no
RestrictNamespaces=no
RestrictRealtime=no
RestrictSUIDSGID=no
LockPersonality=no
RestrictAddressFamilies=
EOF
  printf '[Service]\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n' \
    > /etc/systemd/system/etr-apply.service.d/bind-ports.conf
  printf 'etr-apply (enforce)\netr-apply//nginx_test (enforce)\netr-apply//systemctl (enforce)\n' \
    >> "$test_root/profiles"
}
assert_retired() {
  assert test ! -e /etc/apparmor.d/etr-apply
  assert test ! -e /etc/apparmor.d/local/etr-apply
  assert test ! -e /etc/systemd/system/etr-apply.service.d/profile-transitions.conf
  assert test ! -e /etc/systemd/system/etr-apply.service.d/bind-ports.conf
  if grep -q '^etr-apply' "$test_root/profiles"; then exit 1; fi
  if grep -q '^AppArmorProfile=' /etc/systemd/system/etr-apply.service; then exit 1; fi
}

# Fresh install checks releases but does not opt in to software installation.
bash "$test_root/deploy/install.sh" --from "$test_root/dist"
assert_retired
assert grep -qx 'NGINX_BIN=nginx-sp' /etc/etr/apply.env
assert grep -qx 'User=etr' /etc/systemd/system/etr.service
assert grep -qx 'User=etr' /etc/systemd/system/etr-update.service
assert grep -qx 'AppArmorProfile=-etr-daemon' /etc/systemd/system/etr.service
assert grep -qx 'AppArmorProfile=-etr-update' /etc/systemd/system/etr-update.service
assert grep -q 'CAP_NET_BIND_SERVICE' /etc/systemd/system/etr-apply.service
# An ordinary rerun must preserve an existing disabled updater timer.
: > "$test_root/commands"
bash "$test_root/deploy/install.sh" --from "$test_root/dist"
if grep -q 'systemctl enable --now etr-update.timer' "$test_root/commands"; then exit 1; fi
assert grep -qx 'ETR_AUTO_UPDATE=false' /etc/etr/update-policy.env
assert test -f "$test_root/enabled-etr-check-update.timer"
assert test ! -f "$test_root/enabled-etr-update.timer"
assert grep -qx 'User=etr' /etc/systemd/system/etr-check-update.service
assert grep -qx 'AppArmorProfile=-etr-daemon' /etc/systemd/system/etr-check-update.service
assert grep -qx 'ProtectSystem=strict' /etc/systemd/system/etr-check-update.service
assert runuser -u etr -- test ! -w /etc/etr/update-policy.env
systemd-analyze verify "$repo/deploy/systemd/etr-check-update.service" "$repo/deploy/systemd/etr-check-update.timer"
echo 'PASS fresh install defaults to metadata checks'

# A legacy enabled timer and etr.env do not constitute recorded consent.
rm /etc/etr/update-policy.env
touch "$test_root/enabled-etr-update.timer"
echo ETR_AUTO_UPDATE=true >> /etc/etr/etr.env
bash "$test_root/deploy/install.sh" --from "$test_root/dist"
assert grep -qx 'ETR_AUTO_UPDATE=false' /etc/etr/update-policy.env
assert test ! -f "$test_root/enabled-etr-update.timer"
assert grep -qx 'ETR_AUTO_UPDATE=true' /etc/etr/etr.env
# Explicit consent survives a rerun; explicitly disabling a timer is respected.
bash "$test_root/deploy/install.sh" --from "$test_root/dist" --auto-update
assert grep -qx 'ETR_AUTO_UPDATE=true' /etc/etr/update-policy.env
assert test -f "$test_root/enabled-etr-update.timer"
bash "$test_root/deploy/install.sh" --from "$test_root/dist"
assert grep -qx 'ETR_AUTO_UPDATE=true' /etc/etr/update-policy.env
systemctl disable --now etr-update.timer
bash "$test_root/deploy/install.sh" --from "$test_root/dist"
assert grep -qx 'ETR_AUTO_UPDATE=false' /etc/etr/update-policy.env
bash "$test_root/deploy/install.sh" --from "$test_root/dist" --auto-update
run_install --no-update-check
assert grep -qx 'ETR_AUTO_UPDATE=false' /etc/etr/update-policy.env
assert test ! -f "$test_root/enabled-etr-update.timer"
assert test ! -f "$test_root/enabled-etr-check-update.timer"
bash "$test_root/deploy/install.sh" --from "$test_root/dist"
assert test ! -f "$test_root/enabled-etr-check-update.timer"
systemctl enable --now etr-check-update.timer
echo 'PASS legacy migration, explicit opt-in, revocation and disabled checks'

# Upgrade the exact patched-test-box layout, preserving configuration, staged
# and live lists, and unrelated drop-ins. The mocked services do not run ETR.
seed_old_confinement
touch "$test_root/apply-pending"
printf '[Service]\nReadWritePaths=/etc/nginx-sp/custom.d\n' \
  > /etc/systemd/system/etr-apply.service.d/custom.conf
printf '{"local_blocklist":["192.0.2.1"],"nginx_conf_file_path":"/var/lib/etr/blocklist.conf"}\n' \
  > /etc/etr/config.json
printf 'ETR_RUN_ON_START=false\nINSTANCE_NAME=custom\n' > /etc/etr/etr.env
printf 'ETR_LIVE_FILE=/etc/nginx-sp/http.d/custom.conf\nNGINX_BIN=nginx-sp\nNGINX_SERVICE=nginx-sp\n' > /etc/etr/apply.env
mkdir -p /etc/nginx-sp/http.d
echo 'existing live list' > /etc/nginx-sp/http.d/custom.conf
echo 'existing staged list' > /var/lib/etr/blocklist.conf
for file in /etc/etr/config.json /etc/etr/etr.env /etc/etr/apply.env \
    /etc/nginx-sp/http.d/custom.conf /var/lib/etr/blocklist.conf \
    /etc/systemd/system/etr-apply.service.d/custom.conf; do
  sha256sum "$file" >> "$test_root/preserved.sha256"
done
: > "$test_root/commands"
run_install
assert_retired
assert test ! -f "$test_root/apply-pending"
assert sha256sum -c "$test_root/preserved.sha256"
backups=(/etc/etr/migration-backups/apply.*)
assert test "${#backups[@]}" -eq 1
assert grep -qx 'locally patched legacy profile' "${backups[0]}/etc/apparmor.d/etr-apply"
assert grep -qx 'local policy additions' "${backups[0]}/etc/apparmor.d/local/etr-apply"
assert test -f "${backups[0]}/etc/systemd/system/etr-apply.service.d/profile-transitions.conf"
assert test -f "${backups[0]}/etc/systemd/system/etr-apply.service.d/bind-ports.conf"
assert test "$(stat -c %a /etc/etr/migration-backups)" = 700
assert test "$(stat -c %U /usr/local/sbin/etr-apply)" = root
assert test "$(stat -c %U /opt/etr/bin/etr-linux)" = etr
# Ordering: stop helper -> unload policy -> reload units -> retry existing
# staged file -> restart daemon, even with ETR_RUN_ON_START=false.
assert awk '
  /systemctl stop etr-apply.service/ {stop=NR}
  /apparmor_parser -R/ {unload=NR}
  /systemctl daemon-reload/ {reload=NR}
  /systemctl start etr-apply.service/ {apply=NR}
  /systemctl restart etr.service/ {restart=NR}
  END {exit !(stop && stop<unload && unload<reload && reload<apply && apply<restart)}
' "$test_root/commands"
run_install
assert_retired
assert sha256sum -c "$test_root/preserved.sha256"
backups=(/etc/etr/migration-backups/apply.*)
assert test "${#backups[@]}" -eq 1
echo 'PASS patched-install migration and repeated install'

# --no-mac must still retire a previously loaded executable-path profile.
seed_old_confinement
run_install --no-mac
assert_retired
echo 'PASS retirement with --no-mac'

# The older root-daemon layout must still migrate its live include path.
cp /bin/true /usr/local/bin/etr-linux
printf '{"nginx_conf_file_path":"/etc/nginx-sp/http.d/legacy.conf"}\n' > /etc/etr/config.json
rm /etc/etr/apply.env
run_install
assert test ! -e /usr/local/bin/etr-linux
assert grep -q '"/var/lib/etr/blocklist.conf"' /etc/etr/config.json
assert grep -qx 'ETR_LIVE_FILE=/etc/nginx-sp/http.d/legacy.conf' /etc/etr/apply.env
echo 'PASS root-daemon migration'

# Root scheduling is opt-in. Switching to cron removes/disables the watcher,
# installs only the fixed root validator/unit, and never starts a new apply.
: > "$test_root/commands"
run_install --apply-mode cron
assert test ! -e /etc/systemd/system/etr-apply.path
assert test -f /etc/systemd/system/etr-apply.service
assert test -f /usr/local/sbin/etr-apply
assert grep -qx 'ETR_APPLY_MODE=cron' /etc/etr/apply-mode.env
assert grep -qx 'systemctl disable etr-apply.path' "$test_root/commands"
for trusted in /usr/local/sbin/etr-apply /etc/systemd/system/etr-apply.service \
    /etc/etr/apply.env /etc/etr/apply-mode.env; do
  assert runuser -u etr -- test ! -w "$trusted"
done
assert test ! -e /etc/cron.d/etr-apply
if grep -qE 'systemctl (start etr-apply.service|enable --now etr-apply.path)' "$test_root/commands"; then exit 1; fi
run_install
assert grep -qx 'ETR_APPLY_MODE=cron' /etc/etr/apply-mode.env
echo 'PASS cron mode and mode persistence'

# Generator-only can install without either nginx or the root helper asset.
# Existing root components are retired, with no nginx reload command issued.
mv "$test_root/dist/etr-apply-linux-$arch" "$test_root/unused-helper"
mv "$test_root/bin/nginx-sp" "$test_root/unused-nginx"
: > "$test_root/commands"
run_install --apply-mode generator
assert test ! -e /usr/local/sbin/etr-apply
assert test ! -e /etc/systemd/system/etr-apply.service
assert test ! -e /etc/systemd/system/etr-apply.path
assert grep -qx 'ETR_APPLY_MODE=generator' /etc/etr/apply-mode.env
if grep -qE 'systemctl (start etr-apply.service|enable --now etr-apply.path)' "$test_root/commands"; then exit 1; fi
run_install
assert grep -qx 'ETR_APPLY_MODE=generator' /etc/etr/apply-mode.env
echo 'PASS generator-only mode without nginx or a helper asset'

# Explicitly switching back restores the watcher and validated root workflow.
mv "$test_root/unused-helper" "$test_root/dist/etr-apply-linux-$arch"
mv "$test_root/unused-nginx" "$test_root/bin/nginx-sp"
: > "$test_root/commands"
run_install --apply-mode systemd
assert test -f /usr/local/sbin/etr-apply
assert test -f /etc/systemd/system/etr-apply.path
assert grep -qx 'ETR_APPLY_MODE=systemd' /etc/etr/apply-mode.env
assert grep -qx 'systemctl enable --now etr-apply.path' "$test_root/commands"
assert grep -qx 'systemctl start etr-apply.service' "$test_root/commands"
echo 'PASS switching back to automatic application'

# A failure to unload must leave the old policy files in place and must not
# start the new helper under the lingering policy.
seed_old_confinement
: > "$test_root/commands"
if ETR_TEST_UNLOAD_FAIL=1 run_install; then exit 1; fi
assert test -f /etc/apparmor.d/etr-apply
assert test -f /etc/systemd/system/etr-apply.service.d/profile-transitions.conf
if grep -q 'systemctl restart etr.service' "$test_root/commands"; then exit 1; fi
echo 'PASS unload failure stops migration'

# A current bootstrap script may download an older signed deployment bundle.
# Reject that bundle before touching an existing install or stopping services.
printf '\nAppArmorProfile=-etr-apply\n' >> "$test_root/deploy/systemd/etr-apply.service"
: > "$test_root/commands"
if run_install; then exit 1; fi
if grep -qE 'systemctl (stop|start|enable|disable|restart|daemon-reload) ' "$test_root/commands"; then exit 1; fi
echo 'PASS old deployment bundle rejected before mutation'

# A downloaded release must never fall back to untrusted checksums when the
# host's OpenSSL cannot verify Ed25519. No services may be stopped on failure.
cat > "$test_root/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == -fsSL && $2 == -o ]]
printf 'untrusted download\n' > "$3"
EOF
cat > "$test_root/bin/openssl" <<'EOF'
#!/bin/sh
echo 'old OpenSSL without Ed25519 raw input support' >&2
exit 1
EOF
chmod +x "$test_root/bin/curl" "$test_root/bin/openssl"
: > "$test_root/commands"
if bash "$test_root/deploy/install.sh" --tag v3.99.0 --no-auto-update > "$test_root/unsigned.log" 2>&1; then exit 1; fi
assert grep -q 'refusing to install without verifying the release signature' "$test_root/unsigned.log"
if grep -qE 'systemctl (stop|start|enable|disable|restart|daemon-reload) ' "$test_root/commands"; then exit 1; fi
echo 'PASS unverified release rejected before mutation'
echo 'All native installer checks passed.'

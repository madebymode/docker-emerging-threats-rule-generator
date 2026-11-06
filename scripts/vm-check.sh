#!/usr/bin/env bash
# End-to-end check of a native install on a DISPOSABLE host (VM or systemd
# container). It installs nginx, overwrites /etc/etr/config.json, and
# switches SELinux to enforcing. Never run it on a server you care about.
#
# Usage (as root, from a repo checkout):
#   scripts/vm-check.sh [--no-mac] DIST_DIR
#
# Run it once per platform: on RHEL it requires SELinux enforcing with the
# etr module, on Ubuntu AppArmor with the etr profiles. --no-mac skips those
# checks, for systemd containers that can enforce neither.
#
# DIST_DIR holds etr-linux-ARCH and etr-apply-linux-ARCH built for this host
# (and etr-selinux-elN.pp on RHEL), e.g. from:
#   GOOS=linux GOARCH=arm64 go build -tags native -o dist/etr-linux-arm64 .
#   GOOS=linux GOARCH=arm64 go build -o dist/etr-apply-linux-arm64 ./cmd/etr-apply
#   scripts/check-policies.sh dist
#
# Any SELinux or AppArmor denial for ETR or nginx fails the check: the
# policies must allow everything ETR does, with nothing added by hand.
set -euo pipefail
mac=1
[[ ${1:-} == --no-mac ]] && { mac=0; shift; }
dist=$(cd "${1:?usage: $0 [--no-mac] DIST_DIR}" && pwd)
repo=$(cd "$(dirname "$0")/.." && pwd)
[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 1; }

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
wait_for() { # wait_for SECONDS command...
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || return 1
    sleep 1
  done
}
status_field() { tr -d ' \n' < /var/lib/etr-apply/status.json 2>/dev/null | grep -o "\"$1\":[^,}]*" | cut -d: -f2- | tr -d '"'; }

# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" rhel "*|*" centos "*|*" fedora "*) platform=rhel ;;
  *" ubuntu "*|*" debian "*) platform=ubuntu ;;
  *) echo "unsupported distribution ${ID:-unknown}" >&2; exit 1 ;;
esac
selinux=0 apparmor=0
if [[ $mac -eq 1 && $platform == rhel ]]; then
  selinuxenabled || { echo "FAIL  SELinux is disabled; RHEL hosts must run it" >&2; exit 1; }
  setenforce 1
  selinux=1
elif [[ $mac -eq 1 ]]; then
  [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]] \
    || { echo "FAIL  AppArmor is disabled; Ubuntu hosts must run it" >&2; exit 1; }
  apparmor=1
fi
echo "Platform: $PRETTY_NAME ($platform), SELinux checks: $selinux, AppArmor checks: $apparmor"
start=$(date +%s)

# --- nginx -------------------------------------------------------------------
if ! command -v nginx >/dev/null; then
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get -qq update
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nginx >/dev/null
  else
    dnf -q -y install nginx
  fi
fi
systemctl enable --now nginx >/dev/null 2>&1
cat > /etc/nginx/conf.d/00-etr-check.conf <<'EOF'
server {
    listen 127.0.0.1:8081;
    location / {
        if ($blocked_source) { return 403; }
        return 200 "ok\n";
    }
}
EOF

# --- install -----------------------------------------------------------------
install -d -m 0750 /etc/etr
cat > /etc/etr/config.json <<'EOF'
{
  "local_whitelist": ["192.0.2.4"],
  "local_blocklist": ["192.0.2.0/24", "2001:db8::1", "127.0.0.2"],
  "nginx_conf_file_path": "/var/lib/etr/blocklist.conf"
}
EOF
install_args=(--from "$dist" --nginx nginx --no-auto-update)
[[ $mac -eq 1 ]] || install_args+=(--no-mac)
"$repo/deploy/install.sh" "${install_args[@]}"

# --- first update ------------------------------------------------------------
if wait_for 60 grep -q '"ok":true' /var/lib/etr-apply/status.json; then
  pass "etr-apply reported the first blocklist as installed"
else
  fail "no successful etr-apply result within 60s"
  journalctl -u etr -u etr-apply --no-pager -n 50 || true
fi
check "live include holds whitelist-split entries" grep -q '192.0.2.0/30' /etc/nginx/conf.d/blocklist.conf
check "live include holds IPv6 entries" grep -q '2001:db8::1' /etc/nginx/conf.d/blocklist.conf
check "nginx -t accepts the installed config" nginx -t
check "staged and live files are identical" cmp /var/lib/etr/blocklist.conf /etc/nginx/conf.d/blocklist.conf
# 127.0.0.2 is in the list, 127.0.0.1 is not.
check "nginx blocks a listed address" bash -c '[[ $(curl -s -o /dev/null -w "%{http_code}" --interface 127.0.0.2 http://127.0.0.1:8081/) == 403 ]]'
check "nginx allows an unlisted address" bash -c '[[ $(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8081/) == 200 ]]'

# --- privilege ---------------------------------------------------------------
pid=$(systemctl show -p MainPID --value etr)
check "daemon is running" test "$pid" -gt 0
check "daemon runs as etr" bash -c "[[ \$(ps -o user= -p $pid) == etr ]]"
check "daemon has no capabilities" grep -q 'CapEff:[[:space:]]*0000000000000000' "/proc/$pid/status"
check "daemon has no_new_privs" grep -q 'NoNewPrivs:[[:space:]]*1' "/proc/$pid/status"
check "etr cannot write nginx config" bash -c '! runuser -u etr -- touch /etc/nginx/conf.d/x 2>/dev/null'
check "etr cannot write etr-apply" bash -c '! runuser -u etr -- sh -c "echo > /usr/local/sbin/etr-apply" 2>/dev/null'
check "etr cannot forge the apply result" bash -c '! runuser -u etr -- sh -c "echo > /var/lib/etr-apply/status.json" 2>/dev/null'
check "the daemon refuses to run as root" bash -c '! /opt/etr/bin/etr-linux --force 2>/dev/null'
if [[ $selinux -eq 1 ]]; then
  check "daemon runs in etr_t" bash -c "ps -o label= -p $pid | grep -q ':etr_t:'"
  check "binary is labeled etr_exec_t" bash -c 'ls -Z /opt/etr/bin/etr-linux | grep -q etr_exec_t'
fi
if [[ $apparmor -eq 1 ]]; then
  check "daemon is confined by etr-daemon" grep -q '^etr-daemon (enforce)' "/proc/$pid/attr/current"
fi

# --- hostile staged file -----------------------------------------------------
before=$(sha256sum /etc/nginx/conf.d/blocklist.conf 2>/dev/null || true)
runuser -u etr -- sh -c 'printf "geo \$blocked_source {\n    default \"\";\n}\ninclude /etc/shadow;\n" > /var/lib/etr/.hostile && mv /var/lib/etr/.hostile /var/lib/etr/blocklist.conf'
if wait_for 30 grep -q '"ok":false' /var/lib/etr-apply/status.json; then
  pass "etr-apply rejected a hostile staged file"
else
  fail "etr-apply did not reject a hostile staged file"
fi
check "live include unchanged after rejection" bash -c "[[ \"\$(sha256sum /etc/nginx/conf.d/blocklist.conf)\" == '$before' ]]"
check "rejection does not echo file content" bash -c '! grep -q shadow /var/lib/etr-apply/status.json'
runuser -u etr -- sh -c 'ln -sf /etc/shadow /var/lib/etr/blocklist.conf'
sleep 3
check "etr-apply does not follow a symlink to /etc/shadow" bash -c '! grep -q "root:" /etc/nginx/conf.d/blocklist.conf'
runuser -u etr -- rm -f /var/lib/etr/blocklist.conf
systemctl restart etr
check "daemon restores a good blocklist after restart" wait_for 60 bash -c 'grep -q "\"ok\":true" /var/lib/etr-apply/status.json && cmp -s /var/lib/etr/blocklist.conf /etc/nginx/conf.d/blocklist.conf'

# --- self-update plumbing ----------------------------------------------------
pid=$(systemctl show -p MainPID --value etr)
kill -HUP "$pid"
sleep 3
check "SIGHUP re-executes the daemon in place" bash -c "[[ \$(systemctl show -p MainPID --value etr) == $pid ]] && systemctl is-active --quiet etr"
check "re-exec is logged" bash -c "journalctl -u etr --since @$start --no-pager | grep -q 're-executing'"
# ETR_AUTO_UPDATE=false exits before any download, but still exercises the
# unit, its user and its SELinux domain / AppArmor profile.
cp /etc/etr/etr.env /etc/etr/etr.env.check
echo ETR_AUTO_UPDATE=false >> /etc/etr/etr.env
check "etr-update.service runs" systemctl start etr-update.service
mv /etc/etr/etr.env.check /etc/etr/etr.env

# --- denials -----------------------------------------------------------------
if [[ $selinux -eq 1 ]]; then
  denials=$(ausearch -m AVC,USER_AVC,SELINUX_ERR -ts "$(date -d "@$start" '+%x %X')" 2>/dev/null \
    | grep -E 'etr_|httpd_t' || true)
  if [[ -z $denials ]]; then pass "no SELinux denials"; else fail "SELinux denials:"; echo "$denials"; fi
fi
if [[ $apparmor -eq 1 ]]; then
  denials=$(journalctl -k --since "@$start" --no-pager 2>/dev/null | grep 'apparmor="DENIED"' | grep -E 'etr-' || true)
  if [[ -z $denials ]]; then pass "no AppArmor denials"; else fail "AppArmor denials:"; echo "$denials"; fi
fi

rm -f /etc/nginx/conf.d/00-etr-check.conf
echo
if [[ $failures -eq 0 ]]; then echo "All checks passed."; else echo "$failures check(s) failed."; exit 1; fi

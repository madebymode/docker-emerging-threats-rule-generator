#!/usr/bin/env bash
# Builds the SELinux module against RHEL 8/9/10 policy and parses the AppArmor
# profiles with each supported Ubuntu's parser, in containers. This proves the
# policies load; scripts/vm-check.sh proves they allow what ETR needs.
#
# Usage: scripts/check-policies.sh [OUT_DIR]
#   OUT_DIR  where to write etr-selinux-el{8,9,10}.pp (default: dist/)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
out=${1:-dist}
mkdir -p "$out"
out=$(cd "$out" && pwd)

for el in 8 9 10; do
  echo "== SELinux, EL$el"
  docker run --rm -v "$PWD/deploy/selinux:/src:ro" -v "$out:/out" "rockylinux/rockylinux:$el" bash -euc '
    dnf -q -y install selinux-policy-devel selinux-policy-targeted policycoreutils setools-console make findutils >/dev/null
    cp -r /src /build && cd /build
    make -s -f /usr/share/selinux/devel/Makefile etr.pp
    # Linking into the full policy checks neverallow rules and that every
    # referenced type exists, which compiling alone does not.
    semodule -n -X 300 -i etr.pp
    semodule -n -B
    policy=$(ls /etc/selinux/targeted/policy/policy.* | tail -n1)
    if sesearch -A -s etr_t -t etr_exec_t -c file -p write "$policy" | grep -q .; then
      echo "etr_t can write its own binary" >&2; exit 1
    fi
    sesearch -A -s etr_update_t -t etr_exec_t -c file -p write "$policy" | grep -q . \
      || { echo "etr_update_t cannot write the binary" >&2; exit 1; }
    for t in shadow_t cert_t httpd_config_t; do
      if sesearch -A -s etr_t -t $t -c file -p write "$policy" | grep -q .; then
        echo "etr_t can write $t" >&2; exit 1
      fi
    done
    [ "$(matchpathcon -n /opt/etr/bin/etr-linux)" = system_u:object_r:etr_exec_t:s0 ]
    cp etr.pp /out/etr-selinux-el'"$el"'.pp
  '
done

for ubuntu in 20.04 22.04 24.04 26.04; do
  echo "== AppArmor, Ubuntu $ubuntu"
  docker run --rm -v "$PWD/deploy/apparmor:/src:ro" "ubuntu:$ubuntu" bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update >/dev/null
    apt-get -qq install -y apparmor >/dev/null 2>&1
    for p in etr-daemon etr-update etr-apply; do
      touch /etc/apparmor.d/local/$p
      cp /src/$p /etc/apparmor.d/$p
      apparmor_parser --skip-kernel-load --skip-cache --skip-read-cache /etc/apparmor.d/$p 2>&1 \
        | grep -v "Cache read/write disabled" || true
      apparmor_parser --skip-kernel-load --skip-cache --skip-read-cache /etc/apparmor.d/$p >/dev/null 2>&1
    done
  '
done
echo "Policies OK; SELinux modules in $out"

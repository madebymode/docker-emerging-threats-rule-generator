#!/bin/sh
set -eu

# Runtime user is etr-updater (uid 1000) — no root anywhere.
test "$(id -un)" = etr-updater
test "$(id -u)" = 1000

# Container-level hardening is in place.
grep -q 'CapEff:[[:space:]]*0000000000000000' /proc/self/status
grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status

# Installed binaries must not be writable by the runtime user.
test ! -w /usr/local/bin/nginx_blacklist
test ! -w /usr/local/bin/docker-entrypoint.sh

# The one directory the daemon needs to write.
test -w /app/nginx/conf

# Drop a fixture into the default config location and run --force end-to-end.
cat > /app/config.json <<'JSON'
{
    "local_whitelist": ["1.2.3.4"],
    "local_blocklist": ["1.2.3.0/24", "2001:db8::1"],
    "nginx_conf_file_path": "/app/nginx/conf/blocklist.conf"
}
JSON

# --force runs one update cycle and exits. RESTART_CONTAINERS=false skips the
# Docker socket call — this smoke test runs with --network none by design.
RESTART_CONTAINERS=false /usr/local/bin/nginx_blacklist --force

# Whitelist subtraction produced 1.2.3.0/30 (1.2.3.4 removed); IPv6 preserved.
grep -q '1.2.3.0/30' /app/nginx/conf/blocklist.conf
grep -q '2001:db8::1' /app/nginx/conf/blocklist.conf
test "$(stat -c %a /app/nginx/conf/blocklist.conf)" = 644

# Entrypoint guards against running as root.
grep -q 'container is running as root' /usr/local/bin/docker-entrypoint.sh

echo 'Docker hardening smoke tests passed'

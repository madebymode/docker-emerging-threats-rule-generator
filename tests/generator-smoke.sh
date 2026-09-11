#!/bin/sh
set -eu
cat > /app/config.json <<'JSON'
{"local_whitelist":["1.2.3.4"],"local_blocklist":["1.2.3.0/24","2001:db8::1"],"nginx_conf_file_path":"/app/nginx/conf/blocklist.conf"}
JSON

# Default startup, a new Docker group, and an existing GID all still work.
DOCKER_HOST_GID=34567 /app/docker-entrypoint.sh sh -ec '
    test "$(id -un)" = anubis
    id -G | grep -qw 34567
    for path in /app /app/nginx /app/crontabs /app/nginx_blacklist /app/docker-entrypoint.sh /etc/periodic/daily/update_block_lists; do
        test ! -w "$path"
    done
    test -w /app/nginx/conf
    grep -q "CapEff:[[:space:]]*0000000000000000" /proc/self/status
    grep -q "NoNewPrivs:[[:space:]]*1" /proc/self/status
'
DOCKER_HOST_GID=$(id -g anubis) /app/docker-entrypoint.sh true
RUN_AS_ROOT=true /app/docker-entrypoint.sh sh -ec 'test "$(id -u)" = 0'
su-exec anubis /app/docker-entrypoint.sh sh -ec 'test "$(id -un)" = anubis'
grep -q '1.2.3.0/30' /app/nginx/conf/blocklist.conf
grep -q '2001:db8::1' /app/nginx/conf/blocklist.conf
test "$(stat -c %a /app/nginx/conf/blocklist.conf)" = 644
if DOCKER_HOST_GID=invalid /app/docker-entrypoint.sh true; then
    echo 'Invalid GID was accepted' >&2
    exit 1
fi

# Check the shipped schedule before accelerating it in this disposable container.
grep -q '^30 2 ' /app/crontabs/root
printf '%s\n' '* * * * * /etc/periodic/daily/update_block_lists >> /tmp/etr-cron-output 2>&1' > /app/crontabs/root
crond -f -d 8 -c /app/crontabs > /tmp/etr-crond-output 2>&1 &
cron_pid=$!
trap 'kill "$cron_pid" 2>/dev/null || true' EXIT
attempt=0
until test -f /tmp/etr-cron-output && grep -q 'Blocklist.conf file created successfully' /tmp/etr-cron-output; do
    attempt=$((attempt + 1))
    if test "$attempt" -gt 70; then
        cat /tmp/etr-crond-output
        cat /tmp/etr-cron-output 2>/dev/null || true
        echo 'Cron update did not complete' >&2
        exit 1
    fi
    sleep 1
done
grep -q 'Running cron callable as user anubis' /tmp/etr-cron-output
cat /tmp/etr-cron-output
echo 'Docker hardening smoke tests passed'

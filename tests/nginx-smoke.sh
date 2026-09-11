#!/bin/sh
set -eu
test "$(id -u)" != 0
test ! -w /etc/nginx/conf.d/blocklist.conf
grep -q 'CapEff:[[:space:]]*0000000000000000' /proc/self/status
/docker-entrypoint.sh nginx -g 'daemon off;' > /tmp/nginx-test.log 2>&1 &
nginx_pid=$!
trap 'kill "$nginx_pid" 2>/dev/null || true' EXIT
attempt=0
until wget -q -O /dev/null http://127.0.0.1:8080/check_ip > /dev/null 2>&1; do
    attempt=$((attempt + 1))
    if test "$attempt" -gt 10; then cat /tmp/nginx-test.log; exit 1; fi
    sleep 1
done
status() { wget -S -O /dev/null "$@" http://127.0.0.1:8080/check_ip 2>&1 | awk '{ for (i=1; i<NF; i++) if ($i ~ /^HTTP\/[0-9.]+$/) code=$(i+1) } END { print code }'; }
test "$(status)" = 200
test "$(status -U '')" = 403
test "$(status --header 'X-Forwarded-For: 1.2.3.5')" = 403
test "$(status --header 'X-Forwarded-For: 1.2.3.4')" = 200
test "$(status --header 'X-Forwarded-For: 2001:db8::1')" = 403
test "$(status --header 'X-Forwarded-For: 1.2.3.4, 1.2.3.5')" = 403
grep -q '"blocked_source":"local"' /tmp/nginx-test.log
grep -q '"blocked_ua":"empty-ua"' /tmp/nginx-test.log
nginx -s reload
cat /tmp/nginx-test.log
echo 'Unprivileged nginx smoke tests passed'

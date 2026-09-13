#!/bin/sh
set -eu

log() {
    echo "[$(date '+%Y/%m/%d %H:%M:%S')] $*"
}

log "Starting entrypoint as $(id -un) (uid $(id -u))..."

if [ "$(id -u)" = "0" ]; then
    log "ERROR: container is running as root. This image is designed to run as uid 1000 (etr-updater)."
    log "Remove any 'user: root' override or --user=0 flag."
    exit 1
fi

if [ ! -w /app/nginx/conf/ ]; then
    log "ERROR: /app/nginx/conf/ is not writable by uid $(id -u)."
    log "Named volumes inherit ownership from the image on first run — check that the volume is fresh."
    log "For bind mounts, run: sudo chown -R 1000:987 <host-path>"
    exit 1
fi

log "Handing off to $*"
exec "$@"

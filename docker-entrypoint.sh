#!/bin/sh
set -eu

RUN_AS_ROOT=${RUN_AS_ROOT:-false}
DOCKER_HOST_GID=${DOCKER_HOST_GID:-}

log() {
    echo "[$(date '+%Y/%m/%d %H:%M:%S')] $*"
}

run_as_configured_user() {
    if [ "$(id -u)" = "0" ]; then
        if [ "$RUN_AS_ROOT" = "true" ]; then
            log "Running as root..."
            "$@"
        else
            log "Running as user anubis..."
            su-exec anubis "$@"
        fi
    else
        if [ "$RUN_AS_ROOT" = "true" ]; then
            log "RUN_AS_ROOT=true was requested, but the container is running as $(id -un). Override the container user to root to enable it."
        fi
        log "Running as current user $(id -un)..."
        "$@"
    fi
}

exec_as_configured_user() {
    if [ "$(id -u)" = "0" ]; then
        if [ "$RUN_AS_ROOT" = "true" ]; then
            log "Executing main container command as root..."
            exec "$@"
        else
            log "Executing main container command as anubis user..."
            exec su-exec anubis "$@"
        fi
    else
        if [ "$RUN_AS_ROOT" = "true" ]; then
            log "RUN_AS_ROOT=true was requested, but the container is running as $(id -un). Override the container user to root to enable it."
        fi
        log "Executing main container command as current user $(id -un)..."
        exec "$@"
    fi
}

log "Starting entrypoint script..."

if [ "$(id -u)" = "0" ]; then
    if [ -n "$DOCKER_HOST_GID" ]; then
        case "$DOCKER_HOST_GID" in
            *[!0-9]*) log "DOCKER_HOST_GID must be a numeric group ID."; exit 1 ;;
        esac
        log "DOCKER_HOST_GID is set to $DOCKER_HOST_GID"
        # Reuse a matching GID even when its group is not called docker.
        docker_group=$(getent group "$DOCKER_HOST_GID" | cut -d: -f1)
        if [ -z "$docker_group" ]; then
            docker_group="etr-docker-$DOCKER_HOST_GID"
            addgroup -g "$DOCKER_HOST_GID" "$docker_group"
        fi
        adduser anubis "$docker_group"
    else
        log "DOCKER_HOST_GID is not set. Skipping group adjustments."
    fi

    log "Adjusting permissions of /app/nginx/conf/..."
    chown -Rh anubis:rites /app/nginx/conf/
    log "Permissions adjusted."

    # Cron configuration and executable files remain root-owned from the image.
    # Child processes inherit stdout/stderr; changing device ownership is unnecessary.
else
    if [ -n "$DOCKER_HOST_GID" ]; then
        log "DOCKER_HOST_GID is set, but group changes require root. Use compose group_add with this GID for Docker socket access."
    else
        log "DOCKER_HOST_GID is not set. Skipping group adjustments."
    fi

    if [ ! -w /app/nginx/conf/ ]; then
        log "/app/nginx/conf/ is not writable by $(id -un). Fix the volume owner or run once as root."
        exit 1
    fi
fi

log "Running FIRST etr run..."
run_as_configured_user /app/nginx_blacklist

# Check if the first argument is "crond"
if [ "$1" = "crond" ]; then
    log "Running crond as $(id -un)..."
    exec "$@"
else
    exec_as_configured_user "$@"
fi

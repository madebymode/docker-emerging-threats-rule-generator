#!/bin/sh

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

configure_crontab() {
    cron_dir="/app/crontabs"
    cron_command="30 2 * * * /etc/periodic/daily/update_block_lists >> /proc/1/fd/1 2>&1"

    log "Configuring root crontab..."
    echo "$cron_command" > "$cron_dir/root"
    rm -f "$cron_dir/anubis"
    chown root:root "$cron_dir" "$cron_dir/root"
    chmod 755 "$cron_dir"
    chmod 600 "$cron_dir/root"
}

log "Starting entrypoint script..."

if [ "$(id -u)" = "0" ]; then
    if [ ! -z "$DOCKER_HOST_GID" ]; then
        log "DOCKER_HOST_GID is set to $DOCKER_HOST_GID"
        if ! getent group docker > /dev/null 2>&1; then
            log "Docker group does not exist. Attempting to create with GID $DOCKER_HOST_GID..."
            if addgroup -g "$DOCKER_HOST_GID" docker; then
                log "Docker group created with GID $DOCKER_HOST_GID."
            else
                log "Failed to create Docker group with GID $DOCKER_HOST_GID. It might already be in use."
                exit 1
            fi
        else
            log "Docker group already exists."
        fi

        if getent group docker > /dev/null 2>&1; then
            log "Adding anubis user to the docker group..."
            if adduser anubis docker; then
                log "Anubis user added to the docker group."
            else
                log "Failed to add anubis to the docker group."
                exit 1
            fi
        else
            log "Docker group not found. Cannot add anubis to non-existent group."
            exit 1
        fi
    else
        log "DOCKER_HOST_GID is not set. Skipping group adjustments."
    fi

    log "Adjusting permissions of /app/nginx/conf/..."
    chown -R anubis:rites /app/nginx/conf/
    log "Permissions adjusted."

    # Give the anubis user write access to stdout and stderr
    chown anubis:rites /dev/stdout /dev/stderr

    configure_crontab
else
    if [ ! -z "$DOCKER_HOST_GID" ]; then
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

#!/bin/sh

echo "Starting entrypoint script..."

if [ ! -z "$DOCKER_HOST_GID" ]; then
    echo "DOCKER_HOST_GID is set to $DOCKER_HOST_GID"
    if ! getent group docker > /dev/null 2>&1; then
        echo "Docker group does not exist. Attempting to create with GID $DOCKER_HOST_GID..."
        if addgroup -g "$DOCKER_HOST_GID" docker; then
            echo "Docker group created with GID $DOCKER_HOST_GID."
        else
            echo "Failed to create Docker group with GID $DOCKER_HOST_GID. It might already be in use."
            exit 1
        fi
    else
        echo "Docker group already exists."
    fi

    if getent group docker > /dev/null 2>&1; then
        echo "Adding anubis user to the docker group..."
        if adduser anubis docker; then
            echo "Anubis user added to the docker group."
        else
            echo "Failed to add anubis to the docker group."
            exit 1
        fi
    else
        echo "Docker group not found. Cannot add anubis to non-existent group."
        exit 1
    fi
else
    echo "DOCKER_HOST_GID is not set. Skipping group adjustments."
fi

echo "Adjusting permissions of /app/nginx/conf/..."
chown -R anubis:rites /app/nginx/conf/
echo "Permissions adjusted."


# Check if the RUN_AS_ROOT environment variable is set to "true"
if [ "$RUN_AS_ROOT" = "true" ]; then
    echo "Running as root..."
    # Execute the command directly without su-exec to run as root
    exec "$@"
else
    echo "Executing main container command as anubis user..."
    exec su-exec anubis "$@"
fi




#!/bin/sh
# Runs only disposable containers with fixture data and no Docker socket.
set -eu
image=${1:-etr:hardening-test}

docker build --build-arg "ETR_IMAGE=$image" -f tests/Dockerfile.smoke -t etr:generator-smoke .
docker run --rm --network none \
    --security-opt no-new-privileges:true --pids-limit 128 \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE \
    --cap-add SETUID --cap-add SETGID \
    -e RESTART_CONTAINERS=false etr:generator-smoke
docker build --build-arg "ETR_IMAGE=$image" -f tests/Dockerfile.nginx-smoke -t etr:nginx-smoke .
docker run --rm --network none --read-only \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 etr:nginx-smoke

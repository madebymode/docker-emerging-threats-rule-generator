#!/bin/sh
# Runs only disposable containers with fixture data and no Docker socket.
set -eu
image=${1:-etr:hardening-test}

# Shipped image is FROM scratch: no shell for attackers or CVE scanners.
if docker run --rm --network none --entrypoint /bin/sh "$image" -c true 2>/dev/null; then
    echo 'FAIL: image contains /bin/sh'; exit 1
fi

# Startup preflight refuses root and an unwritable rules directory.
expect_refusal() {
    msg=$1; shift
    if out=$(docker run --rm --network none -e RESTART_CONTAINERS=false "$@" "$image" 2>&1); then
        echo "FAIL: container started ($*)"; exit 1
    fi
    echo "$out" | grep -q "$msg" || { echo "FAIL: missing '$msg' in: $out"; exit 1; }
}
expect_refusal 'running as root' --user 0
expect_refusal 'is not writable' --read-only

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

# syntax=docker/dockerfile:1

FROM golang:1.27.3-alpine3.24 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY *.go ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nginx_blacklist

# Assemble the runtime filesystem here; the final stage has no shell or apk.
RUN apk add --no-cache tzdata \
    && mkdir -p /rootfs/etc/ssl/certs /app-skel/nginx/conf \
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ \
    && cp /usr/share/zoneinfo/America/New_York /rootfs/etc/localtime \
    && echo "America/New_York" > /rootfs/etc/timezone \
    && echo "etr-updater:x:1000:987::/app:/sbin/nologin" > /rootfs/etc/passwd \
    && echo "etr-updater:x:987:" > /rootfs/etc/group \
    && chown -R 1000:987 /app-skel

# No OS packages at runtime: nothing for base-image CVE scanners to flag.
FROM scratch

COPY --from=build /rootfs/ /
# COPY resets ownership to root unless --chown is given.
COPY --from=build --chown=1000:987 /app-skel/ /app/
COPY --from=build /out/nginx_blacklist /usr/local/bin/nginx_blacklist

USER 1000:987
WORKDIR /app

# Daemon mode: the binary self-schedules its own runs (default 03:00 local
# with up to 60min jitter). PID 1 is the Go binary — Docker's SIGTERM reaches
# it directly for clean shutdown.
ENV ETR_DAEMON=true

CMD ["/usr/local/bin/nginx_blacklist"]

FROM golang:1.27.1-alpine3.24 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nginx_blacklist

FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 987 etr-updater \
    && adduser -S -D -H -u 1000 -G etr-updater etr-updater \
    && mkdir -p /app/nginx/conf \
    && ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime \
    && echo "America/New_York" > /etc/timezone \
    && chown -R etr-updater:etr-updater /app

COPY --from=build /out/nginx_blacklist /usr/local/bin/nginx_blacklist
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER etr-updater
WORKDIR /app

# Daemon mode: the binary self-schedules its own runs (default 03:00 local
# with up to 60min jitter). PID 1 is the Go binary — Docker's SIGTERM reaches
# it directly for clean shutdown.
ENV ETR_DAEMON=true

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/nginx_blacklist"]

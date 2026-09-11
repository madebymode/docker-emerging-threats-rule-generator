# Use a versioned Go Alpine image for building
FROM golang:1.27.1-alpine3.24 AS build

# Set the working directory
WORKDIR /app

# Copy only build inputs; local configuration and credentials never enter a layer.
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

# This app needs no C libraries or runtime compiler toolchain.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o nginx_blacklist

# Use a smaller Alpine image for running the binary
FROM alpine:3.24

# Set the working directory
WORKDIR /app

# Copy the binary from the build image
COPY --from=build /app/nginx_blacklist .
COPY docker-entrypoint.sh .
COPY docker-cronjob /etc/periodic/daily/update_block_lists

# Combine all of our run tasks for the smallest img possible
# Install tzdata and other dependencies
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata su-exec \
    && addgroup -S rites \
    && adduser -S anubis -G rites \
    && mkdir -p /app/nginx/conf /app/crontabs \
    && chmod +x nginx_blacklist \
    && chmod +x docker-entrypoint.sh \
    && chmod +x /etc/periodic/daily/update_block_lists \
    && ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime \
    && echo "America/New_York" > /etc/timezone \
    && chown -R root:root /app \
    && chmod 755 /app /app/nginx /app/crontabs \
    && chown anubis:rites /app/nginx/conf \
    && echo "30 2 * * * /etc/periodic/daily/update_block_lists >> /proc/1/fd/1 2>&1" > /app/crontabs/root \
    && chmod 600 /app/crontabs/root \
    && chown root:root /app/crontabs/root

# Socket access is opt-in via an explicit bind mount, never an anonymous volume.

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Run PID 1 as root so BusyBox crond can read the root-owned spool.
# The entrypoint and cron wrapper run the ETR command as anubis by default.
USER root

# Default command runs crond
CMD ["crond", "-f", "-d", "8", "-c", "/app/crontabs"]

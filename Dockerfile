# Use a versioned Go Alpine image for building
FROM golang:1.26-alpine3.23 AS build

# Set the working directory
WORKDIR /app

# Install Git, build-base, and other dependencies
RUN apk add --no-cache git openssh build-base tzdata

# Copy the source code to the container
COPY . .

# Download the dependencies
RUN go mod download

# Enable CGO and build the binary
ENV CGO_ENABLED=1
RUN go build -o nginx_blacklist

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
RUN apk add --no-cache tzdata su-exec \
    && addgroup -S rites \
    && adduser -S anubis -G rites \
    && mkdir -p /app/nginx/conf /app/crontabs \
    && chmod +x nginx_blacklist \
    && chmod +x docker-entrypoint.sh \
    && chmod +x /etc/periodic/daily/update_block_lists \
    && ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime \
    && echo "America/New_York" > /etc/timezone \
    && chown -R anubis:rites /app \
    && chown root:root /app/crontabs \
    && echo "30 2 * * * /etc/periodic/daily/update_block_lists >> /proc/1/fd/1 2>&1" > /app/crontabs/root \
    && chmod 600 /app/crontabs/root \
    && chown root:root /app/crontabs/root

# Use a volume to share Docker socket from the host
VOLUME ["/var/run/docker.sock"]

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Run PID 1 as root so BusyBox crond can read the root-owned spool.
# The entrypoint and cron wrapper run the ETR command as anubis by default.
USER root

# Default command runs crond
CMD ["crond", "-f", "-d", "8", "-c", "/app/crontabs"]

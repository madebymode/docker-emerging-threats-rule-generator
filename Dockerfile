# Use a versioned Go Alpine image for building
FROM golang:1.22.4-alpine3.20 AS build

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
FROM alpine:3.20

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
    && chmod +x nginx_blacklist \
    && chmod +x docker-entrypoint.sh \
    && chmod +x /etc/periodic/daily/update_block_lists \
    && ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime \
    && echo "America/New_York" > /etc/timezone \
    && chown -R anubis:rites /app \
    && mkdir -p /var/spool/cron/crontabs \
    && echo "30 2 * * * /etc/periodic/daily/update_block_lists" > /var/spool/cron/crontabs/root \
    && chmod 600 /var/spool/cron/crontabs/root \
    && chown root:root /var/spool/cron/crontabs/root

# Use a volume to share Docker socket from the host
VOLUME ["/var/run/docker.sock"]

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Default command runs crond
CMD ["crond", "-f", "-l", "8", "-L", "/dev/stdout"]

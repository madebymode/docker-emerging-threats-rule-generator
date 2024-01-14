# Use a versioned Go Alpine image for building
FROM golang:1.21.6-alpine3.18 AS build

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
FROM alpine:3.18

# Install required libraries
RUN apk add --no-cache tzdata su-exec

# Create a new user and group
RUN addgroup -S rites && adduser -S anubis -G rites

# Set the working directory
WORKDIR /app

# Copy the binary from the build image
COPY --from=build /app/nginx_blacklist .
COPY --from=build /app/docker-entrypoint.sh .

# Make the binary executable
RUN chmod +x nginx_blacklist
RUN chmod +x docker-entrypoint.sh

# Setup Cron
# Copy your cron job script to the daily directory
COPY docker-cronjob /etc/periodic/daily/update_block_lists
RUN chmod +x /etc/periodic/daily/update_block_lists

# Set timezone if needed (example: America/New_York)
RUN ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime && \
    echo "America/New_York" > /etc/timezone

# Change ownership of the working directory and necessary files
RUN chown -R anubis:rites /app

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Start the cron daemon
CMD ["crond", "-f", "-l", "8"]

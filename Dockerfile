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

# Set the working directory
WORKDIR /app

# Copy the binary from the build image
COPY --from=build /app/nginx_blacklist .
COPY docker-entrypoint.sh .
COPY docker-cronjob /etc/periodic/daily/update_block_lists

# combine all of our run tasks for the smallest img possible
RUN apk add --no-cache tzdata su-exec \
&& addgroup -S rites && adduser -S anubis -G rites \
&& chmod +x nginx_blacklist \ 
&& chmod +x docker-entrypoint.sh \
&& chmod +x /etc/periodic/daily/update_block_lists \
&& ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime && \
echo "America/New_York" > /etc/timezone \
&& chown -R anubis:rites /app

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# update our list on container start then run cron daemon to update once daily
CMD /app/nginx_blacklist && crond -f -l 8


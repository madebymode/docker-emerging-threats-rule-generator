# Emerging Threat Rules for Nginx — v1 (Legacy)

> **This is the v1 legacy branch.** v1 is no longer actively developed. For new deployments, use [v2](https://github.com/mxmd/docker-emerging-threats-rule-generator/tree/master) which provides per-source labeling, user-agent blocking, and structured access logs.
>
> **Compatibility note:** The `$blocked_ip` variable used by v1's generated `blocklist.conf` and `nginx/default.conf` is **not compatible with v2**. v2 generates a different blocklist format using `$blocked_source` (a labeled geo variable). Do not mix v1 config files with a v2 image or vice versa.

Docker Hub:

https://hub.docker.com/repository/docker/mxmd/etr

## Overview

This Dockerized Go application automates the generation of an Nginx `blocklist.conf` file from dynamic emerging threat
lists. It is designed to update the blocklist daily, helping you secure your servers against known malicious IP
addresses.

The application executes as a daily cron job inside the container, ensuring the `blocklist.conf` file is updated with
the latest emerging threat IPs.

## Configuration

The application requires a `config.json` file to specify the URLs for the emerging threat lists and the output path for
the `blocklist.conf` file. Here is a template for the `config.json`:

```json
{
  "block_lists": [
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  ],
  "nginx_conf_file_path": "/app/nginx/conf/blocklist.conf",
  "nginx_container_names": [
    "docker-emerging-threats-rule-generator-nginx-blacklist-1",
    "docker-emerging-threats-rule-generator-nginx-blacklist-2"
  ]
}
```

Adjust the `block_lists` array with the URLs of your chosen emerging threat lists and set the `nginx_conf_file_path` to
the desired path within your Nginx container.

## How the Nginx Blocklist Works (v1)

v1 generates a `blocklist.conf` using nginx's [`geo` module](https://nginx.org/en/docs/http/ngx_http_geo_module.html). The file looks like this:

```nginx
# blocklist.conf

geo $blocked_ip {
    default        0;

    1.2.3.4        1;
    5.6.7.0/24     1;
    ...
}
```

The `$blocked_ip` variable is `1` for any request whose `$remote_addr` (or real IP via `set_real_ip_from`) matches a listed address, and `0` otherwise. The included `nginx/default.conf` checks this variable on the `/check_ip` endpoint:

```nginx
server {
    listen 80;

    location /check_ip {
        if ($blocked_ip) {
            return 403;
        }
        return 200 "OK";
    }
}
real_ip_header      X-Forwarded-For;
set_real_ip_from 172.0.0.0/8;
```

> **v2 incompatibility:** v2 replaces `$blocked_ip` with `$blocked_source`, a labeled geo variable that identifies which blocklist matched. v1's `blocklist.conf` and `nginx/default.conf` will not work with a v2 image — they use a different variable name and file format.

## Using with Nginx

To apply the generated `blocklist.conf` in Nginx, mount the named volume (`nginx-blocking-rules`) used by the
`nginx_blacklist` container to your Nginx container. This setup allows Nginx to use the updated blocklist without manual
intervention.

## Docker Compose

For ease of deployment, a `docker-compose.yml` file is provided. It orchestrates both the `nginx_blacklist` application
and an Nginx container, ensuring they are configured to share the blocklist file. Here is a simplified example:

```yaml
version: '3'

services:
  emerging-threats-rules:
    environment:
      # change the DOCKER_HOST_GID to match the docker group on the host - using "grep docker /etc/group | cut -d: -f3" - this is typically a 100x user
      - DOCKER_HOST_GID=1003
      # only run as root in debugging scenerios, or if your docker host is running something like a boot2docker iso where the docker gid lower than 1000 as this can cause conflicts with alpine
      - RUN_AS_ROOT=false
    image: mxmd/etr
    build: .
    volumes:
      - ./config.json:/app/config.json:ro
      - nginx-blocking-rules:/app/nginx/conf/
      - /var/run/docker.sock:/var/run/docker.sock

  nginx-blacklist:
    depends_on:
      - emerging-threats-rules
    image: nginx:alpine
    volumes:
      - "nginx-blocking-rules:/etc/nginx/conf.d/"
      - "./nginx/default.conf:/etc/nginx/conf.d/default.conf"

volumes:
  nginx-blocking-rules:
```

a more detailed approach using traefik would look something like this

```yaml
services:
  traefik:
    healthcheck:
      test: ["CMD", "traefik", "healthcheck", "--ping"]
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: always
    image: "traefik:v2.11.0"
    container_name: "traefik"
    command:
      - "--ping=true" # Enables the /ping health check endpoint
      - "--entrypoints.ping.address=:8082" # Creates a new entrypoint for ping on a port not exposed outside
      - "--log.level=DEBUG"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
      - "--entrypoints.web.http.redirections.entrypoint.permanent=true"
      # access log
      - "--accesslog=true"
      # your other traefik cmds for acme, redirections...etc
    ports:
      - "80:80"
      - "443:443"
    volumes:
      # Add Docker as a mounted volume, so that Traefik can read the labels of other services
      - /var/run/docker.sock:/var/run/docker.sock:ro
    labels:
      - "traefik.enable=true"

      # YOUR existing traefik routers/middlewares/etc

      # @HERE we Define global emerging threat blacklist middleware
      - "traefik.http.middlewares.etr-blocklist.forwardauth.address=http://etr-blocker-nginx/check_ip"
    networks:
      # Use the public network created to be shared between Traefik and
      # any other service that needs to be publicly available with HTTPS
      - traefik-public


  etr-downloader:
    image: mxmd/etr
    restart: always
    # change the DOCKER_HOST_GID to match the docker group on the host - using "grep docker /etc/group | cut -d: -f3"
    environment:
      - DOCKER_HOST_GID=1003
      - RUN_AS_ROOT=false
    volumes:
      # our config.json
      - ./etr/config.json:/app/config.json:ro
      # named volume for saving rules
      - nginx-blocking-rules:/app/nginx/conf/
      # docker socket for restarting nginx (etr-blocker-nginx) containers
      - /var/run/docker.sock:/var/run/docker.sock

  etr-blocker-nginx:
    deploy:
      replicas: 2 # Number of instances
    depends_on:
      - etr-downloader
    image: nginx:alpine
    restart: always
    volumes:
      - "nginx-blocking-rules:/etc/nginx/conf.d/"
      - "./etr/nginx/default.conf:/etc/nginx/conf.d/default.conf"
    # this docker alias needs to be resolvable by other containers
    networks:
      - traefik-public
volumes:
  nginx-blocking-rules:
```

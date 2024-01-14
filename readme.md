# Dynamic Threat Blocklist Generator with Docker

## Overview

This Dockerized Go application generates an Nginx `blocklist.conf` file from dynamic emerging threat lists.

## Prerequisites

- Docker
- Basic knowledge of Docker and Go

## Building the Image

```sh
docker build -t nginx_blacklist .
```

## Running the Container

```sh
docker run -d --name anubis nginx_blacklist
```

The application runs as a daily cron job inside the container, updating the `blocklist.conf` file. Use the named volume in an nginx container to block emerging threats.

## Configuration

Edit `config.json` to specify URLs for the emerging threat lists and the output path for the `blocklist.conf` file.
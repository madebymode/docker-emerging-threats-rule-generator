# Verify nginx blocking on a test deployment

[Documentation index](readme.md) · [Automated checks](CONTRIBUTING.md) · [nginx integration](docs/nginx.md)

Use a disposable deployment for these tests. They exercise the forward-auth
checker at `/check_ip`; inline reverse-proxy examples need requests to the
application route instead. For native installation checks, use
[native verification](native-install.md#5-verify).

## Prepare the fixture

Create a working Docker deployment with the
[first-run sequence](docs/docker.md#quick-start). For predictable results, add
`192.0.2.42` to `local_blocklist` in the test `config.json`, ensure it is not
whitelisted, and run a refresh. Do not depend on a live threat feed continuing
to contain a particular address.

The commands below assume the basic example from the repository root:

```bash
export COMPOSE_FILE=docker-compose.example.yml
docker compose exec emerging-threats-rules /usr/local/bin/nginx_blacklist --force
docker compose exec nginx-blacklist sh
```

Only nginx has a shell. The ETR generator image is `scratch`; invoke its binary
directly. If using another example, substitute its service names.

## Normal request and empty User-Agent

Inside the nginx container:

```bash
# Expect 200 if loopback is not blocked and the User-Agent is present.
wget -S -O - -U ETR-test http://localhost:8080/check_ip

# Expect 403 from the example's independent empty-User-Agent rule.
wget -S -O - -U "" http://localhost:8080/check_ip
```

## Test a forwarded client address

Loopback is not in the default trusted proxy ranges, so nginx normally ignores
`X-Forwarded-For` sent from an in-container request. For this disposable test,
add `set_real_ip_from 127.0.0.1;` at `http` level in the host's
`nginx/default.conf`, then recreate nginx from the host:

```bash
docker compose up -d --force-recreate nginx-blacklist
docker compose exec nginx-blacklist sh
```

Inside nginx, send a normal User-Agent and the fixture address:

```bash
wget -S -O - \
  --header="X-Forwarded-For: 192.0.2.42" \
  --header="X-Forwarded-Method: GET" \
  --header="X-Forwarded-Proto: https" \
  --header="X-Forwarded-Host: test.example" \
  --header="X-Forwarded-Uri: /fixture" \
  http://localhost:8080/check_ip
```

Expect 403 and an IP block label in the log. Remove the temporary loopback trust
rule and recreate nginx when finished. Config files are mounted read-only in
nginx; make edits on the host.

## Check logs and the real proxy route

From the host:

```bash
docker compose logs --no-log-prefix -f nginx-blacklist
```

Check `ip`, `status`, `blocked_source`, and `blocked_ua`. Both reason fields can
be populated when a blocked address also sends an empty User-Agent. The default
configuration logs 403s, not successful requests.

Finally send requests through your actual edge proxy and verify the logged
client address. Local spoofing tests prove the checker reads a trusted header;
they do not prove the edge discards untrusted headers. Review the
[proxy trust boundary](docs/nginx.md#real-ip-trust).

For automated, network-isolated fixtures, run `make docker-smoke`. See
[Contributing](CONTRIBUTING.md#build-and-integration-checks) for the rest of the
validation workflow.

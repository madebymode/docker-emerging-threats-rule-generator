# Deployment examples

[Documentation index](../readme.md) · [Docker setup](../docs/docker.md) · [nginx integration](../docs/nginx.md)

Each directory is a starting point for one proxy arrangement. Configuration is
kept local to each example so you can copy and inspect it without a generator or
template engine. If changing shared nginx behavior, review every example too.

| Directory | Request path |
| --- | --- |
| [traefik-v2](traefik-v2/) | Traefik forward-auth → nginx `/check_ip` → app |
| [traefik-v3](traefik-v3/) | Same pattern with v3 configuration notes |
| [caddy](caddy/) | Caddy `forward_auth` → nginx `/check_ip` → app |
| [nginx-reverse-proxy](nginx-reverse-proxy/) | nginx checks rules directly before proxying |
| [pfsense](pfsense/README.md) | pfSense HAProxy → nginx inline checks → app |

Before starting an example:

1. Copy the chosen directory to your deployment location. Create its
   `config.json` from [config.example.json](../config.example.json).
2. Set `nginx_container_names` to the example's actual nginx container name.
   Inspect `container_name` in Compose or check `docker compose ps`.
3. Review feed sources, local whitelist entries, domains, upstream application
   names/ports, published ports, and TLS settings.
4. Set `group_add` for your host's Docker socket group, or remove socket access
   and configure an external apply/reload workflow. Socket access is host-level
   authority on rootful Docker.
5. Narrow trusted proxy addresses in nginx and configure the edge proxy to
   discard untrusted forwarded headers.
6. Generate an initial list before nginx starts. Follow the
   [first-run sequence](../docs/docker.md#quick-start), substituting the example's
   generator service name (usually `etr-downloader`). `depends_on` does not
   guarantee the file is ready.

Use [manual testing](../testing.md) to check actual client IPs and block results.
Do not assume that a successful container start means the intended sites are
protected.

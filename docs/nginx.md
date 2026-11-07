# nginx integration

[Documentation index](../readme.md) · [Docker setup](docker.md) · [Native placement](../native-install.md#3-nginx-placement)

## Generated data and enforcement

| File | Responsibility |
| --- | --- |
| Generated `blocklist.conf` | Defines `geo $blocked_source` with IP/CIDR entries and source labels |
| Supplied `nginx/default.conf` | Reads that variable, serves `/check_ip`, and configures JSON logging |
| Native enforcement snippets | Apply the same decision in each protected site |

A `geo` block belongs at nginx's `http` level. Generating or including the data
alone does not reject a request: a request-handling rule must use its value.
The native installer leaves site enforcement and request logging to the
operator. See the [nginx geo reference](https://nginx.org/en/docs/http/ngx_http_geo_module.html).

`$blocked_source` is empty for an address with no matching entry. Otherwise it
contains a source label such as `local`, `ipsum-6`, or a joined label such as
`ipsum-6+compromised-ips`. Labels describe the generated matching entry; overlapping
CIDRs may select the most specific match rather than every source containing
that client address.

## Checker behavior

The forward-auth examples listen on container port 8080 and expose `/check_ip`:

| Condition | Result |
| --- | --- |
| Empty User-Agent | 403 |
| Address matches generated rules | 403 |
| Neither | 200 |

The empty User-Agent rule is independent of the IP whitelist. Both
`blocked_source` and `blocked_ua` can be populated in a log record; testing the
User-Agent first does not erase the IP match. Remove the empty User-Agent rule
if that is not part of your policy.

The reverse-proxy and pfSense examples apply the decision before `proxy_pass`
instead of exposing a separate authorization hop. Inspect the configuration
for the example you deploy.

## Real IP trust

nginx must evaluate the client address, not an intermediate proxy's address.
The examples use `real_ip_header X-Forwarded-For` and `real_ip_recursive on`.
With a trusted connecting proxy, recursive lookup selects the last address in
the forwarded chain that is not trusted. See the
[nginx real-IP reference](https://nginx.org/en/docs/http/ngx_http_realip_module.html).

Set `set_real_ip_from` to the actual proxy addresses or dedicated proxy networks
for your deployment. The broad private ranges in examples are placeholders,
not a safe trust policy for every network. Any peer inside a trusted range can
supply a replacement client address. Isolate the checker from direct public
access and configure the edge proxy to discard untrusted forwarded headers.

When a CDN or load balancer sits in front of the edge proxy, configure that
proxy's trusted upstream addresses too. Recursive nginx lookup does not make
an already-forged header trustworthy. Test the complete route through the
edge, using the [manual verification guide](../testing.md).

## Block logs

The default Docker configuration logs 403 responses as JSON to stdout. Fields
include `ip`, `time`, `method`, `url`, `status`, `blocked_source`, and `blocked_ua`.
Forwarded method/host/protocol/URI headers provide display context; they are
not identity or authentication evidence. JSON escaping prevents those values
from breaking the log format.

Native snippets use the Aetos format documented in
[native-install.md](../native-install.md#4-enforcement-and-block-logging).
[reporting.md](../reporting.md) contains queries for both stdout captures and
operator-configured file logs.

## Performance expectations

ETR writes CIDRs into nginx's geo lookup rather than generating a long sequence
of access-control directives. Reloading nginx rebuilds its in-memory lookup.
Measure reload duration, memory, and proxy-hop latency with your own rule count
and traffic. This repository does not establish a universal latency or memory
budget for a deployment.

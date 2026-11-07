# Architecture and source map

[Documentation index](../readme.md) · [Contributing](../CONTRIBUTING.md)

## Build variants

The root Go package builds one generator executable in two variants. Keeping
shared processing in one package lets both variants use the same feed parsing,
whitelist subtraction, output formatting, and notification code.

| Build | Selection | Runtime integration |
| --- | --- | --- |
| Docker generator | Default, `!native` | `docker.go`: Docker API restarts; `/app` configuration and output |
| Native generator | `-tags native` | `native.go`: root-helper acknowledgement; `/etc/etr` configuration and `/var/lib/etr` staging |
| Root helper | `./cmd/etr-apply` | Separate executable; validates data, installs a live include, tests/reloads nginx |

Build tags are part of the security boundary. Native release verification,
software installation, and release notifications are excluded from the Docker
build. The root helper does not import the generator package or its network
clients. Its shared grammar lives in `internal/blocklistfmt`.

The module name `nginx_blacklist` and existing executable/configuration names
are retained for compatibility. A name cleanup should not silently change
installed paths, import paths, or deployment assets.

## Feed refresh path

1. `main.go` selects a CLI mode or starts the daemon loop.
2. `schedule.go` calculates the next local-time window and validates integer
   environment settings.
3. `refresh.go` fetches whitelists and blocklists, merges entries, applies the
   blocklist-source failure threshold, and reports failures.
4. `network.go` parses addresses and performs CIDR overlap/subtraction.
5. `blocklist.go` derives safe labels, subtracts whitelist ranges, sorts output,
   and atomically replaces the generated file.
6. `apply.go` coordinates snapshots and rollback. `docker.go` or `native.go`
   supplies the deployment-specific test/reload behavior.

Native `systemd` mode waits for a root-owned status file matching the staged
content hash and generation time. `cron` and `generator` modes stage data
without waiting. Docker restarts use the Engine API; API success is not an
nginx health check. Handled-error rollback is not durable crash recovery.

## Native software lifecycle

| Source | Responsibility |
| --- | --- |
| `release_manifest.go` | Eligible tags, embedded-key parsing, signed metadata verification and version ordering |
| `release_keys.go` | Embeds public signing keys at build time |
| `update.go` | Explicit opt-in, executable replacement, daemon signalling and rollback |
| `update_check.go` | Metadata-only release discovery and optional availability notifications |
| `update_notice.go` | Bounded, directory-anchored notification-state reads and atomic writes |

The release checker and self-updater share verification, not installation.
Checking never calls executable replacement. The installed checker unit uses
the daemon's confinement; the updater has separate permission to replace the
unprivileged executable. Only installer reruns update the root helper and units.

## Other source files

| Source | Responsibility |
| --- | --- |
| `config.go` | JSON configuration and unknown-key warnings |
| `security.go` | Feed HTTP policy, size/time limits, path/name validation and URL redaction |
| `notify.go` | Notification interface, environment loading and dispatch |
| `notify_http.go` | Telegram, Slack and generic HTTP webhook delivery |
| `notify_smtp.go` | SMTP delivery |
| `notify_standard_webhook.go` | Standard Webhooks payload and signature protocol |
| `cmd/etr-apply/main.go` | Root application, live-file rollback and status reporting |
| `internal/blocklistfmt` | Restricted grammar accepted across the privilege boundary |

## Deployment files

| Location | Owner and purpose |
| --- | --- |
| `deploy/install.sh` | Root-run installation, policy choices and migrations; preserve operator configuration |
| `deploy/systemd/` | Service/timer/path units and OS sandbox settings |
| `deploy/apparmor/` | Ubuntu daemon/updater profiles; no custom helper profile |
| `deploy/selinux/` | RHEL daemon/updater/helper domains and file labels |
| `nginx/` | Default forward-auth checker configuration |
| `examples/` | Deployment-specific proxy configuration; intentionally readable standalone examples |
| `log-manager/` | Optional rotation for an explicitly configured file log |
| `.github/workflows/` | CI, image builds, native assets and signed release publication |
| `scripts/` | Policy/VM checks and release-key maintenance |
| `tests/` | Disposable Docker fixtures and installer integration checks |

Go tests live next to their code. The older `main_test.go`, `blocklist_test.go`,
and `nginx_test.go` also contain shared parsing and end-to-end generation cases;
start with test function names when searching. `TestMain` relaxes output/HTTP
policy for fixtures, so security tests must explicitly restore or call the
production validation function. Tests that mutate package globals are not
parallel-safe.

## Maintenance boundaries

Keep these distinctions visible in code and reviews:

- Feed refresh versus software installation versus metadata-only checking.
- Staged data versus the live nginx include.
- Unprivileged executable versus separately installed root helper.
- Successful notification delivery versus merely attempting a notification.
- Syntax/fixture tests versus live enforcing-MAC and nginx deployment tests.

The [security review](../security-review.md) tracks unresolved functional risks.
Use it to plan separate behavior changes, not as a claim that a passing test
suite proves all deployments safe.

# ETR project review — 2026-11-07

This review covers the working tree, including the native installation and
apply-mode changes. It is a source review with local tests, not a penetration
test or a guarantee that no vulnerabilities exist. Nothing was published or
installed on the remote test server during this review.

## Recommendation

Keep threat-feed refreshes automatic. For production, prefer administrator-
controlled software updates through signed `.deb` and `.rpm` packages. Disable
ETR self-update in package installations and make the executable and its parent
directories root-owned. Run the generator as `etr`; offer the root validator as
an optional component for automatic or administrator-scheduled application.

Follow-up implementation: software installation now requires explicit opt-in.
Fresh installs enable daily metadata-only checks; installer reruns migrate legacy
enabled timers to check-only unless `--auto-update` is supplied. The checker
verifies signed metadata, logs release availability, and optionally notifies
configured channels with per-channel deduplication and weekly reminders.
It runs as `etr` with executable files read-only. APT/DNF packages are still
not implemented. See [native-install.md](native-install.md#6-software-release-checks-and-opt-in-updates).

Package installation still grants our releases substantial authority: package
maintainer scripts can run as root. Packaging replaces custom update mechanics
with familiar administrator controls; it does not remove the need for protected
signing, release review, and recovery procedures. See Debian's
[third-party repository trust guidance](https://wiki.debian.org/DebianRepository/UseThirdParty).

## Fixed in this working tree

| Finding | Change and verification |
| --- | --- |
| `--self-update` bypassed the ordinary native root preflight because flags were handled first. A manual root invocation could execute the downloaded version probe as root. The shipped updater service already used `User=etr`. | Reject root at entry to `selfUpdate()`. Tested the refusal in a network-isolated Linux container running as root. Never execute an `etr`-writable binary as root even with this guard: compromised code can remove it. |
| A FIFO at the staged blocklist path could hang the root helper during open, before its regular-file check. | Open nonblocking through `os.Root`, then check the opened descriptor's file type. Regression test verifies prompt FIFO rejection. |
| The bootstrap installer fell back to checksum verification without authenticating the manifest on unsupported OpenSSL versions. | Fail closed when Ed25519 signature verification is unavailable. Installer regression test confirms rejection before service mutation. |
| Rerunning installation could re-enable a disabled software-update timer. | Preserve disabled timer state unless `--auto-update` is explicit. Installer migration test covers preservation. |
| Download failures and whitelist diagnostics could log URL credentials/query tokens; notification transport errors could expose Telegram or webhook URL tokens. | Redact feed URLs in failures and diagnostics; remove request URLs from notification errors. Regression tests cover HTTP errors, connection failures, malformed URLs, and notification tokens. Feed URL paths remain visible for source identification, so do not put secrets in feed paths. |

The earlier requested installation changes are also in this tree: retirement
of the custom helper AppArmor profile, migration backups, retained daemon and
updater confinement, and `systemd`, `cron`, and `generator` apply modes.
Only `systemd` mode installs an automatic apply watcher. `cron` mode installs
the fixed validator/unit but leaves root scheduling to the administrator.
`generator` mode does not install a root helper. No mode authorizes executing
downloaded generator code as root or including its writable staging file
directly in a privileged nginx instance.

## Remaining findings, in priority order

1. **High: Docker socket access defeats the intended host privilege boundary.**
   The main compose files and deployment examples mount `docker.sock` and grant
   the generator access. Against a rootful daemon, a compromised generator can
   use the API to obtain host-level control. UID 1000, dropped capabilities,
   and `no-new-privileges` do not restrict that API authority. Set
   `RESTART_CONTAINERS=false`, remove the socket and group grant, and arrange
   a separately controlled apply/reload workflow. A future broker needs an
   actual operation/container allowlist, not unrestricted Docker API forwarding.
   See [Docker's daemon security model](https://docs.docker.com/engine/security/).

2. **High for automated deployments: Docker publication is outside the native
   release-signing gate.** `.github/workflows/build-and-release.yml` pushes
   images in the build job, and `master` pushes move `mxmd/etr:v3`. The native
   signing job waits for the `release-signing` environment, but the Docker
   publication does not. Automatically following that tag therefore does not
   provide the same release-review boundary. Gate production image promotion
   and use reviewed immutable digests. This review did not inspect the actual
   repository's required reviewers, tag protections, registry permissions, or
   secret scope. Merely naming an environment does not configure its protection
   rules; see [GitHub's environment documentation](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

3. **Medium: feed URL checks have a DNS rebinding gap.** `security.go` resolves
   and validates addresses, then the HTTP transport resolves again. Redirects
   are checked, but the eventual connection is not bound to the validated IP.
   Fix with connection-time address enforcement and explicit proxy behavior.
   Do not claim complete SSRF protection from the current preflight check.

4. **Medium: remote whitelist failure can broaden blocking.** `runUpdate()`
   logs a failed whitelist fetch and continues without those exemptions.
   Blocklist failure thresholds do not cover whitelists. Prefer retaining the
   previous effective list and alerting when a required whitelist cannot be
   fetched; specify how empty or malformed successful responses are handled.

5. **Medium: apply rollback covers handled errors, not process crashes.** The
   root helper installs before testing/reloading, holds the previous data in
   memory, and treats identical live bytes as already applied. Termination
   between those steps can lose rollback state or skip a required reload on
   the next attempt. Add durable transaction/recovery state. Also bound helper
   subprocess runtimes without killing rollback mid-flight. Docker's restart
   API success is not a health check: nginx can exit after a successful start,
   so existing comments describing Docker rollback are stronger than the
   runtime guarantee.

6. **Medium: availability remains exposed to hostile data or releases.** The
   root grammar rejects arbitrary directives, oversized files and individually
   broad prefixes, but many permitted prefixes can still block essentially
   everyone. The 256 MiB staging limit and two-million-entry default also allow
   substantial parsing/nginx resource consumption. A compromised generator
   can repeatedly stage changes. Consider root-controlled application rate and
   resource limits, protected exemptions, and change-size approval thresholds.
   Package-managed updates do not remove this data-level authority.

7. **Operational hardening: SMTP and proxy trust.** `smtp.SendMail` has no
   configured deadline here, so a stalled server can block notifications and
   the scheduled update cycle. TLS is opportunistic when unauthenticated SMTP
   is used. Nginx examples trust broad private ranges for forwarded client IPs;
   narrow these to actual trusted proxies and isolate the check endpoint.
   A peer within a trusted range can otherwise supply a forged client address.

8. **Release trust and key rotation need an operational procedure.** Bootstrap
   fetches the installer and public key from the same repository used for
   releases; it cannot independently protect against compromise of that
   initial trust source. Self-update instead uses embedded trusted keys.
   `scripts/new-release-key.sh` immediately changes the signing secret, while
   existing binaries do not yet trust the new key. Planned rotation needs an
   old-key-signed bridge release carrying the new public key before signing
   switches; compromise recovery needs a separate administrator action.

## Logging and coverage

Native service output is connected to journald by the installed units.
Nginx enforcement, blocked-request JSON logging, log retention/forwarding,
and notifier credentials need operator configuration. Installing a geo list
alone does not enforce blocking. Software-update availability alerts are opt-in through the separate release
checker; the self-updater does not send them.

Reviewed areas include generator/config/feed processing, nginx formatting,
native status acknowledgement and rollback, root helper and validator, update
verification and replacement, installer/migrations, systemd and MAC policies,
Docker image and compose/examples, nginx/proxy configuration, notifications,
log rotation, CI, signing scripts, and release/install documentation. Tests
exercise selected cases; they cannot establish every possible runtime state.

Validation performed:

- Default and native full Go suites; race checks with `-short`; `go vet` for
  both build variants. An initial full race run exceeded the existing five-
  second performance test limit; the intended separate full and race suites
  passed without changing that limit.
- Docker image build and generator/nginx smoke tests passed.
- Installer filesystem/migration tests passed, including prior test-box
  overrides, apply modes, nonroot ownership checks, disabled updater retention,
  old-bundle rejection, and signature-verification prerequisite failure.
  systemd/AppArmor kernel operations are simulated there; Ubuntu 24.04 policy
  parsing, helper unit verification and shell lint use real tools.
- Root preflight/self-update guards passed in an isolated Linux arm64 container.
- `govulncheck` reported no known reachable vulnerabilities for default and
  native builds. This is database/call-graph evidence, not proof of security.
- Diff whitespace checks passed.

Still required before rollout: a new signed deployment bundle containing these
changes, live ServerPilot installation/upgrade testing, and enforcing-MAC VM
checks across supported Ubuntu/RHEL versions. The full cross-distribution
policy matrix was not rerun as part of this review. APT/DNF repositories and packages remain unimplemented. The follow-up release
checker and opt-in defaults require a new release and live installation testing.

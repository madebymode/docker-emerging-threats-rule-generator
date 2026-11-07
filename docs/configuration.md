# Configuration reference

[Documentation index](../readme.md) · [Docker setup](docker.md) · [Native setup](../native-install.md)

## Files and ownership

| Deployment | Feed configuration | Environment | Output |
| --- | --- | --- | --- |
| Docker | `/app/config.json`, mounted read-only | Compose `environment` or `env_file` | `/app/nginx/conf/blocklist.conf` on the rules volume |
| Native | `/etc/etr/config.json`, root-owned | `/etc/etr/etr.env`, root-owned | `/var/lib/etr/blocklist.conf`, staged for separate application |

Start with [config.example.json](../config.example.json), then choose sources
and exemptions appropriate for your sites. Native installation creates its own
initial config with the native output path. Do not copy a Docker output path
into a native installation.

## JSON fields

| Field | Meaning |
| --- | --- |
| `remote_blocklists` | HTTPS feed URLs. Each source contributes IPs/CIDRs and a label in the generated file. |
| `local_blocklist` | Inline IPs/CIDRs to include, subject to whitelist exclusions. |
| `remote_whitelists` | HTTPS feeds containing IPs/CIDRs to exclude from blocking. |
| `local_whitelist` | Inline IPs/CIDRs to exclude from blocking. |
| `nginx_conf_file_path` | Generated file within the allowed output directory shown above. |
| `nginx_container_names` | Docker runtime container names to restart. Use `docker compose ps` to check names; Compose service names are not necessarily container names. Ignored in native builds. |
| `nginx_service_name` | Legacy accepted field; unused. Native nginx selection belongs in `/etc/etr/apply.env`. |

Unknown keys produce a warning. The example file is a starting point, not an
implicit fallback when configuration is missing.

## Feed parsing and whitelists

Feeds can contain IPv4/IPv6 addresses and CIDRs. Blank lines and lines starting
with `#` are ignored. The parser also extracts addresses from some mixed-text
feeds; do not assume an HTTP 200 response proves a feed contains valid entries.
Downloads are limited to 50 MiB and 30 seconds. HTTPS and public-address checks
apply to feed requests and redirects; the remaining DNS rebinding limitation
is documented in the [security review](../security-review.md).

Whitelists subtract addresses from the generated IP blocklist. They do not
bypass the example nginx rule for an empty User-Agent, or other access controls.
All local and remote whitelist entries are combined. For example, blocking
`198.51.100.0/24` and whitelisting `198.51.100.5` produces smaller CIDRs covering
the original network except that address:

```text
198.51.100.0/30    # .0 through .3
198.51.100.4/32    # .4
                  # .5 is excluded
198.51.100.6/31    # .6 through .7
198.51.100.8/29    # .8 through .15
...               # remaining ranges through .255
```

A failed remote whitelist download currently logs an error and continues
without that source's exemptions. Keep essential exemptions local until the
failure policy is changed. See [remaining findings](../security-review.md#remaining-findings-in-priority-order).

## Scheduling and application

| Variable | Default | Meaning |
| --- | --- | --- |
| `ETR_DAEMON` | `false` in the binary; `true` in the image and native unit | Schedule feed refreshes in-process. `--force` runs once regardless. |
| `ETR_AT_HOUR` | `3` | Local-time hour for daily feed refreshes, 0–23. |
| `ETR_JITTER_MINUTES` | `60` | Additional randomized delay, 0–240 minutes. |
| `ETR_RUN_ON_START` | `true` | Set to `false` to wait for the next window. A missing output file still triggers an initial refresh. |
| `RESTART_CONTAINERS` | enabled unless exactly `false` | Skip Docker API access when false. The daemon keeps scheduling refreshes; this does not make it exit. Native cron/generator modes also skip automatic apply acknowledgement. |
| `BLOCKLIST_FAILURE_THRESHOLD` | `30` | Abandon the refresh when the integer failure percentage is **at least** this value. Range 0–100. With remote blocklists configured, 0 abandons every refresh, even with no failed downloads; 100 abandons when all fail. There is no disable sentinel. |
| `INSTANCE_NAME` | unset | Label added to notification subjects. |
| `TZ` | image: `America/New_York`; native: host timezone | Timezone for scheduling and log timestamps. |
| `HTTPS_PROXY`, `NO_PROXY` | unset | Standard Go HTTP proxy settings. Configure proxies as trusted infrastructure. |

Feed-refresh scheduling and software-release checks are separate. Native apply
modes, helper settings, software opt-in, and alert reminders are documented in
[native-install.md](../native-install.md). Docker software upgrades are managed
by replacing the image.

## Command-line modes

| Flag | Behavior |
| --- | --- |
| `--force` | Run one feed refresh and exit. Does not install software. |
| `--version` | Print the embedded build version. |
| `--check-update` | Native only: verify release metadata, log availability, optionally notify. |
| `--self-update` | Native only: install software when explicitly enabled. Refuses root. |

Do not run an `etr`-writable executable as root. Use the installed systemd units
for privileged application and native maintenance.

## Notification channels

Configured channels receive feed-refresh and apply failures. The native release checker also uses these channels when `ETR_UPDATE_NOTIFY=true`. See [native software checks](../native-install.md#6-software-release-checks-and-opt-in-updates).

**Telegram**

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | _(unset)_ | Bot token from @BotFather. Both token and chat ID must be set to enable Telegram. |
| `TELEGRAM_CHAT_ID` | _(unset)_ | Target chat or channel ID. |

**Email (SMTP / STARTTLS)**

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | _(unset)_ | SMTP server hostname. All three of host, from, and to must be set to enable email. |
| `SMTP_PORT` | `587` | SMTP port; STARTTLS is used when the server offers it. |
| `SMTP_FROM` | _(unset)_ | Sender address. |
| `SMTP_TO` | _(unset)_ | Comma-separated list of recipient addresses. |
| `SMTP_USER` | _(unset)_ | SMTP username — omit for unauthenticated relay. |
| `SMTP_PASS` | _(unset)_ | SMTP password. |

**Slack (bot)**

| Variable | Default | Description |
|---|---|---|
| `SLACK_BOT_TOKEN` | _(unset)_ | Bot User OAuth token (starts with `xoxb-`). Requires the `chat:write` scope. Invite the bot to the target channel. |
| `SLACK_CHANNEL_ID` | _(unset)_ | Channel ID (e.g. `C0123ABC456`) — use the channel ID, not the `#name`. Find it in Slack via *View channel details → About → (bottom)*. |

**Webhook**

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | _(unset)_ | URL to POST `{"subject":"…","body":"…"}` (JSON) on notable events. |

**Standard Webhooks (signed)**

Signs each POST per the [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks) spec — receivers verify with `webhook-id`, `webhook-timestamp`, and `webhook-signature: v1,<base64>` headers over the canonical string `<msg_id>.<timestamp>.<raw_body>`.

| Variable | Default | Description |
|---|---|---|
| `STANDARD_WEBHOOK_URL` | _(unset)_ | Destination URL. Both URL and SECRET must be set to enable. |
| `STANDARD_WEBHOOK_SECRET` | _(unset)_ | HMAC key. Accepts `whsec_<base64>` (per spec — decoded before use) or a bare string. |
| `STANDARD_WEBHOOK_FROM` | `INSTANCE_NAME` → `ETR` | Value sent as `data.from` in the envelope. |
| `STANDARD_WEBHOOK_EVENT_TYPE` | `slack.notification` | Envelope `type`. Receivers route on this; use whatever hierarchical identifier the receiver expects (e.g. `slack.notification`, `slack.alert`). |
| `STANDARD_WEBHOOK_SLACK_CHANNEL_ID` | _(unset)_ | Optional per-sender Slack channel override. Preferred over the name — stable across renames. |
| `STANDARD_WEBHOOK_SLACK_CHANNEL_NAME` | _(unset)_ | Optional Slack channel name override. Sent when configured; receiver decides precedence if both ID and name are set. |

Payload shape (envelope, camelCase fields):

```json
{
  "type": "slack.notification",
  "timestamp": "<RFC 3339>",
  "data": {
    "from": "<from>",
    "body": "<body>",
    "title": "<subject>",
    "slackChannelId": "<optional>",
    "slackChannelName": "<optional>"
  }
}
```

For interop with mode-iris: point `STANDARD_WEBHOOK_URL` at `https://<iris>/messaging/standard` and share the same secret.

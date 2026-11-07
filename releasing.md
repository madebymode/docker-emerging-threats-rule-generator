# Releasing

[Documentation index](readme.md) · [Contributing](CONTRIBUTING.md)

There are two kinds of release:

| | Trigger | GitHub release | Docker tags | Installed by native hosts |
|---|---|---|---|---|
| **Development build** | every push to `master` | `v3-YYYY-MM-DD-HHMMSS`, unsigned | `v3`, `master`, `v3-YYYY-MM-DD-HHMMSS` | never |
| **Signed release** | pushing a `v3.MINOR.PATCH` tag | `v3.MINOR.PATCH`, signed | `3.MINOR.PATCH`, `v3.MINOR.PATCH`, `v3` | only with explicit opt-in, by `etr-update.timer` |

## Cutting a signed release

1. **Pick the version.** Follow [Semantic Versioning](https://semver.org/):
   bump the patch (`v3.0.0` → `v3.0.1`) for fixes, the minor (`v3.0.1` →
   `v3.1.0`) for new features or config options. It must match
   `v3.MINOR.PATCH` exactly; the job refuses anything else (no `-rc1`), and
   hosts only install v3 releases. List existing ones with
   `git tag -l 'v3.*' --sort=-v:refname`.

2. **Check `master` is green.** The tag builds whatever commit it points to,
   so tag a commit whose `Go` and `Build and Release` runs passed:

   ```bash
   git switch master && git pull --ff-only
   gh run list --branch master -L 4
   ```

3. **Tag and push.**

   ```bash
   git tag -a v3.1.0 -m "v3.1.0"
   git push origin v3.1.0
   ```

   This starts **Build and Release Cross-Platform** on the tag. It runs the
   tests, pushes the Docker image, builds the native binaries with the tag
   compiled in (`etr-linux --version`) and records GitHub build provenance
   for them. Follow it with `gh run watch` or in the Actions tab.

4. **Approve signing.** After a few minutes the `sign-release` job waits for a
   reviewer of the `release-signing` environment. Open the run
   (`gh run view --web`), click **Review deployments**, tick
   `release-signing` and **Approve and deploy**. The job then:
   - bundles `deploy/` and the SELinux modules into `etr-deploy.tar.gz`;
   - writes `manifest.json` (tag, time, SHA-256 of every binary and the
     bundle), signs it with Ed25519 and checks the signature against
     `release-signing.pub`;
   - creates a draft release, attaches the binaries, `etr-deploy.tar.gz`,
     `manifest.json` and `manifest.json.sig`, then publishes it.

   Rejecting it publishes no GitHub release, but the Docker tags from step 3
   are already pushed.

5. **Write the release notes.** The workflow's notes are generic. Edit the
   release on GitHub to say what changed, and call out anything that needs
   `install.sh` rerun: self-update replaces only the daemon, so changes to
   `etr-apply`, a unit or a policy reach a host only when someone reruns
   `install.sh`.

   For the apply-helper AppArmor retirement, publish the updated deployment
   bundle in the signed release before directing users to rerun installation.
   The current bootstrap installer rejects older bundles that still ship the
   helper profile. The migration unloads that profile, backs up the test-box
   troubleshooting drop-ins, and preserves configuration; daemon self-update
   alone cannot perform it. Native installer migration tests gate signing.
   The install-mode feature also requires the new daemon binary and deployment
   bundle together: old daemons do not understand cron/generator staging mode.
   The bootstrap rejects bundles without the managed mode environment file.

6. **Verify it** (optional, anyone can do this):

   ```bash
   mkdir /tmp/etr-v3.1.0 && cd /tmp/etr-v3.1.0
   gh release download v3.1.0 -R madebymode/docker-emerging-threats-rule-generator \
     -p 'manifest.json*' -p etr-linux-amd64
   curl -fsSLO https://raw.githubusercontent.com/madebymode/docker-emerging-threats-rule-generator/v3.1.0/release-signing.pub
   openssl pkeyutl -verify -rawin -pubin -inkey release-signing.pub \
     -in manifest.json -sigfile manifest.json.sig      # Signature Verified Successfully
   sha256sum etr-linux-amd64; jq -r '.assets["etr-linux-amd64"]' manifest.json   # must match
   gh attestation verify etr-linux-amd64 -R madebymode/docker-emerging-threats-rule-generator
   ```

The release-check feature needs the new binary and deployment bundle together.
The installer enables `etr-check-update.timer` by default and disables legacy
software installation unless `--auto-update` is explicitly supplied. Publish
those units and the update-policy environment support in the same signed
release; the bootstrap rejects older bundles. Self-update alone does not perform
that installer migration.

## After it is published

Hosts explicitly opted into `etr-update.timer` install a release once it is older than
`ETR_UPDATE_DELAY_HOURS` (default 72), counted from the signed manifest time.
New hosts, and hosts on a build older than the signing setup, need one manual
install with `deploy/install.sh` (see [native-install.md](native-install.md)).

**A bad release:** withdraw it promptly. Hosts may already have installed it
through a manual install, a pin, or a shorter waiting period. Deleting it (`gh release delete v3.1.0 --cleanup-tag`) prevents subsequent downloads
from that release. Then fix `master`
and release the next patch version; never reuse a version number.

**A failed run:** fix the problem on `master`, then release the next patch
version. Re-running the failed jobs from the Actions tab also works if the
cause was transient.

## One-time setup (repository admin)

1. **Signing environment:** create `release-signing` under Settings →
   Environments. Add yourself (and one other maintainer) as required
   reviewers, and limit deployments to tags matching `v3.*`.
2. **Signing key:** run `scripts/new-release-key.sh ~/etr-release-key.pem`,
   commit the updated `release-signing.pub`, and move the backup offline.
   The first binaries that self-update are the ones released after this commit;
   install those by hand once (see [native-install.md](native-install.md)).
3. **Repository protection:**
   - Settings → General → Releases: enable **immutable releases**.
   - A tag ruleset for `v3.*`: block updates, deletions and force pushes.
   - A branch ruleset for `master`: require a pull request with one approval
     and block force pushes.

## Rotating the key

Existing hosts must learn a new public key before releases are signed with it.
The current `scripts/new-release-key.sh` immediately changes the signing secret;
use it for initial setup, not as a complete rotation procedure.

For planned rotation:

1. Generate and back up the new private key securely. Append its public key to
   `release-signing.pub`, leaving the old key first and the signing secret
   unchanged. The workflow verifies signatures against the first public key.
2. Publish a bridge release signed with the old key and containing both public
   keys. Deploy that release to the managed fleet before changing the signer.
3. Move the new public key to the first position and replace the signing secret
   with the new private key. Publish the next release signed with the new key.
4. Remove the old public key in a later release after completing the migration.

Hosts that missed the bridge release cannot authenticate a release signed only
with the new key. Recover those hosts through an administrator-controlled install
with an independently verified key. Do not assume the updater can skip directly
to the newest release across a trust-key change.

If a private key is compromised, stop automatic installation and use an
independently verified recovery path. Pinning a version alone does not revoke a
compromised key. Coordinate key replacement and host recovery before resuming
updates; do not rely on an old-key-signed bridge as proof of trust.

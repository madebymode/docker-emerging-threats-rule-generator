# Releasing

Every push to `master` publishes the Docker image and a timestamped release
(`v3-YYYY-MM-DD-HHMMSS`). Native hosts never install those automatically.

Native self-update (`etr-update.timer`) installs only **signed `v3.MINOR.PATCH`
releases**. Pushing such a tag runs the `sign-release` job, which:

1. builds both binaries with the tag compiled in (`etr-linux --version`) and
   records GitHub build provenance for them;
2. waits for approval in the `release-signing` environment;
3. writes `manifest.json` (tag, time, SHA-256 of each binary), signs it with
   Ed25519, and checks the signature against `release-signing.pub`;
4. creates a draft release, attaches the binaries, manifest and signature,
   then publishes it.

Hosts install a release once it is older than `ETR_UPDATE_DELAY_HOURS`
(default 72), counted from the signed manifest time. If a release is bad,
delete it inside that window and no host will have installed it.

```bash
git tag v3.2.0 && git push origin v3.2.0
# approve the sign-release job in the Actions tab
```

Anyone can check a binary's provenance:

```bash
gh attestation verify etr-linux-amd64 -R madebymode/docker-emerging-threats-rule-generator
```

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

Run the script again. It puts the new public key first in
`release-signing.pub` and replaces the environment secret. Release once with
both keys present, so hosts receive binaries that trust the new key. Then
remove the old key in a later release.

If the private key is compromised, remove its line from `release-signing.pub`
and release immediately. Hosts on older binaries still trust the old key until
they update, so also pin them (`ETR_UPDATE_PIN`) or update them manually.

# Working on ETR

Start with the [architecture and source map](docs/architecture.md). Installation
and operator settings are in the [documentation index](readme.md).

## Local tools

Use the Go version declared in `go.mod`, Git, and Make. Docker is needed for
image, installer, and policy checks. ShellCheck is used by CI and the installer
test container. You can run the underlying commands without Make; `make help`
lists the available targets.

```bash
make fmt
make check
make race
```

`make check` checks formatting, runs full tests, and runs `go vet` for both
Docker and native variants. Race checks use `-short` because the full suite
contains a wall-clock performance test. Do not increase that threshold merely
to accommodate race instrumentation.

## Build and integration checks

```bash
make build                         # host binaries in ignored bin/
make docker-smoke IMAGE=etr:dev     # builds locally; no publication
make installer-test                # disposable Ubuntu filesystem
make policies                      # supported Ubuntu/RHEL policy matrix
```

Host-built native/helper binaries are useful for compilation checks; native
services target Linux. Use `GOOS=linux GOARCH=amd64` or `GOARCH=arm64` when
building deployment assets. The release workflow creates versioned binaries
and signed deployment bundles.

| Change | Additional validation |
| --- | --- |
| Shared generation or HTTP handling | Both Go variants; relevant generation/security tests |
| Native release checking or updating | Native tests; signature failures, explicit opt-in and no-install checks |
| Root helper or grammar | Helper and grammar tests; rollback and hostile-input cases |
| Installer or systemd units | `make installer-test`; live upgrade on a disposable host |
| AppArmor or SELinux policy | `make policies`; enforcing-MAC VM checks |
| Dockerfile or nginx configuration | `make docker-smoke`; manual proxy testing when routing changes |
| Documentation | Check local links, examples and commands against the implementation |

Installer tests simulate systemd and AppArmor kernel operations. Policy parsing
is not proof of runtime permission compatibility. `scripts/vm-check.sh` changes
a host's configuration and is for disposable machines only; read it before use.

## Code organization

- Keep shared code independent of native/Docker integration. Put variant-specific
  code behind the appropriate build tag and test both builds.
- Give each file one responsibility. Prefer a small named function when it
  clarifies a boundary; avoid abstractions that only hide a short operation.
- Write comments for ownership, failure behavior, security assumptions and
  non-obvious algorithms. Do not restate every line or promise more than the
  implementation guarantees.
- Use `gofmt` for all Go files. `.editorconfig` supplies editor defaults for the
  other formats. Preserve protocol payloads and fixtures when formatting.
- Keep the root helper small. Do not introduce downloads, shell evaluation, or
  execution of `etr`-writable files into a root path.
- Do not change external configuration names or installed paths as cosmetic
  cleanup. Document migration when behavior or compatibility changes.

## Documentation organization

`readme.md` is the entry point. Detailed Docker, configuration, nginx, and
architecture guides live in `docs/`. Existing root-level native, testing,
reporting, migration and release guides keep their public URLs. Put an option's
full explanation in one reference and link to it from other guides.

When changing a setting, update its reference, examples, relevant unit comments,
and tests together. Describe the behavior that ships, including limitations.
Keep proposals clearly separate from implemented features. Use relative links
for repository files and primary sources for external technical claims.

## Review and release

Keep a formatting/file-move commit separate from subsequent behavior fixes when
practical. State what changed, why, which checks ran, and what still requires a
live test. Avoid incidental dependency or generated-file changes.

Use [releasing.md](releasing.md) for publication. Ordinary `make` targets never
publish artifacts or alter host service configuration. The legacy
`local-docker-buildx.sh` is a manual publishing script: it pushes the moving
`mxmd/etr:v3` tag and removes Docker builders/changes contexts. It is not part of
the normal development or reviewed release workflow; do not run it for tests.

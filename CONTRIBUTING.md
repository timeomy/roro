# Contributing

Thanks for helping. Roro is small on purpose; changes that keep it small,
auditable, and fail-closed are the easiest to accept.

## Ground rules

- **Original work only.** Do not paste code from other MCP gateways or
  scanners. Reading them for ideas is fine; say where an idea came from in
  `docs/architecture.md`.
- **Fail closed.** If a component cannot decide, the call is denied.
- **No secrets in output.** Logs, audit events, approval prompts, and
  telemetry carry redacted arguments or none at all.
- **Authorization lives in Cedar**, not in YAML or Go conditionals. YAML
  wires things up; Go computes facts (paths, hosts, matcher results, counts)
  that policy uses.
- Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## Development

```sh
go test -race ./...        # unit + end-to-end tests
./scripts/demo.sh          # the attack demo
gofmt -l . && go vet ./...
```

Requires Go 1.27+. `CGO_ENABLED=0` builds must keep working.

Add a test with every behaviour change. For anything in the decision path
(`internal/gate`, `internal/policy`, `internal/audit`), include a test that
shows the unsafe case is denied, not only that the safe case is allowed.

If you add or upgrade a dependency, run `./scripts/third-party-licenses.sh`
and commit `third_party/LICENSES.txt`.

## Commits and pull requests

Conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`). Fill in the pull request template, including how you tested.

## Cutting a release

1. Add a section at the top of [CHANGELOG.md](CHANGELOG.md):
   `## 0.4.0 (2026-12-01): One line on what the release is about`. Write it
   for the person updating, not for the commit log. Put anything they must
   check after updating under "Good to know".
2. Set `version` and `date-released` in [CITATION.cff](CITATION.cff).
3. Tag and push: `git tag v0.4.0 && git push origin v0.4.0`.

The release workflow refuses to publish if the changelog has no section for
the tag or the citation file names another version. The release title and
notes come from the changelog section.

By contributing you agree your contribution is licensed under Apache-2.0.

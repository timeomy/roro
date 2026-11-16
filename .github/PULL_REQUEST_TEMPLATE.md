## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## How it was tested

- [ ] `go test -race ./...`
- [ ] `./scripts/demo.sh`
- [ ] New or changed behaviour has a test (for the decision path: a test that the unsafe case is denied)

## Checklist

- [ ] Fails closed on errors
- [ ] No secrets in logs, audit events, approval prompts, or telemetry
- [ ] Docs updated (README, docs/, CLI help) if behaviour changed
- [ ] `third_party/LICENSES.txt` regenerated if dependencies changed

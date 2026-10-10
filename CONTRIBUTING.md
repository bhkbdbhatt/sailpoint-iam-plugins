# Contributing to Sentinel

Thanks for taking the time to contribute. Sentinel is an identity & access
governance platform built in Go, and we welcome bug reports, feature requests,
documentation, and code.

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Be
respectful and constructive.

## Getting started

- Requires **Go 1.27+**. Everything else (`golangci-lint`) is optional locally —
  CI runs it for you.
- Clone the repo, then:

```bash
go build ./...        # compiles
go vet ./...          # static analysis
go test ./...         # tests
./scripts/coverage.sh coverage.out 70   # coverage gate (70% overall)
```

- Install `golangci-lint` (v2.x) and run `golangci-lint run ./...`.
- Fuzz targets run like normal tests during CI smoke; run them locally with:

```bash
go test -fuzz FuzzVerifyPassword -fuzztime 10s ./internal/auth/
go test -fuzz FuzzFileSnapshotLoad -fuzztime 10s ./internal/store/
```

## Development workflow

1. **Open an issue first** for anything non-trivial, so work isn't duplicated
   and the design can be discussed. See `docs/operations.md` / `docs/security.md`
   for background on the runtime and threat model.
2. **Fork + branch.** Use a descriptive branch name, e.g.
   `feat/connector-xyz` or `fix/owner-resolution`.
3. **Code.** Match the existing style; do not add comments unless they explain a
   non-obvious decision. New exported symbols need doc comments.
4. **Test.** Add or update tests. New functionality requires coverage — there is
   a hard 70% overall gate in CI, plus ≥80% for `auth` and `store`.
5. **Verify locally** — the CI equivalent is:

```bash
gofmt -l .                      # must be empty (run gofmt -w on diffs)
go vet ./...
golangci-lint run ./...
go test -race ./...
./scripts/coverage.sh coverage.out 70
```

6. **Push and open a pull request.** Reference the issue number. Keep PRs small
   and reviewable; split unrelated work into separate PRs.

## Project conventions

- **Testing**: table-driven where sensible; `package` (white-box) tests for
  internals like the store, `_test` package for the HTTP surface.
- **Errors**: wrap with `fmt.Errorf("...: %w", err)`; compare with `errors.Is`
  against `model.Err*` sentinels, never `==`.
- **Store contracts**: every mutation must maintain its indexes
  (`userEmail`, `identityExt`, etc.) — `loadSnapshot` + `rebuildIndexes` is the
  reference implementation.
- **API**: any route, parameter, or response-shape change MUST be mirrored in
  `openapi/openapi.yaml` (validated in CI) and ideally in the README route table.
- **Secrets**: never log, print, or return plaintext connector secrets or keys.

## Adding a connector

1. Implement the `connector.Connector` interface (`Key`, `Discover`).
2. Register it in `connector.Default()`.
3. Add mocks and tests (see `internal/connector/aws_iam_test.go` for the mock-SDK
   pattern), including pagination and failure cases.
4. Document setup and least-privilege permissions (see
   `docs/connector-aws-iam.md`).

## Commit message style

Small, imperative, ≤ 50 characters for the subject; body explains the *why*.
Example:

```
Fix owner resolution failing for cross-system grants

Grants referencing an identity by external id could not be
resolved when the referenced record was upserted after the grant;
resolve owners in a second pass.
```

## Filing issues / feedback

Use the templates in `.github/ISSUE_TEMPLATE/`:

- **Bug report** — steps to reproduce, expected vs. actual, environment.
- **Feature request** — problem statement and proposed behavior.
- **Security** — follow the disclosure process in `SECURITY.md`, do **not** open
  a public issue for vulnerabilities.
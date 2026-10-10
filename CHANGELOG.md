# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Beta release plan (`PLAN.md`).
- Apache-2.0 license.
- **Live AWS IAM connector** (`aws_iam`): discovers users, roles, groups,
  access keys and policy attachments; least-privilege IAM policy documented in
  `docs/connector-aws-iam.md`.
- **OpenAPI 3.1 spec** (`openapi/openapi.yaml`, embedded via `go:embed`) served
  at `/openapi.yaml`, with an interactive Swagger UI at `/docs`.
- Prometheus metrics (`/metrics`) and a `/readyz` readiness probe.
- Release/CI tooling: `.goreleaser.yaml`, `Dockerfile`, `docker-compose.yml`,
  `.golangci.yml`, GitHub Actions workflow with a 70% overall coverage gate.
- Test suite expanded: connector runner ref-resolution, scheduler, AWS IAM
  mocks, bootstrap idempotency, file-store concurrent writes, API key lifecycle,
  rate limiting, RBAC detail cases, secrets box, model validation, CLI.
- Fuzz targets for `auth.VerifyPassword` and the file-store snapshot loader.
- Load test scenario (k6) for login + identities + overview (`load/`).
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `docs/operations.md`,
  `docs/security.md`, and GitHub issue/feedback templates.

### Changed
- Default store backend is now the file-backed store (`SENTINEL_STORE=file`).
- `auth.VerifyPassword` rejects malformed argon2id hashes (empty salt/hash,
  zero or excessive memory/timing parameters) instead of panicking.
- Connector results may reference identities and resources by source-system
  external id (owners, grant subjects and targets); the runner resolves them to
  internal UUIDs after upserting referenced records.

### Fixed
- `auth.VerifyPassword` parsed argon2id hashes incorrectly (expected 6 `$`
  segments, the encoder emits 5), which caused every login to fail.
- RBAC package did not compile (missing `model.` qualifiers and methods declared
  on the non-local `model.Role` type); replaced with `auth.Can` and
  `auth.Permissions`.
- `store.Memory` user update did not maintain the email index on email change.
- AWS IAM connector: pagination used a dereferenced pointer boolean and policy
  attachments were not tenant-scoped.

## [0.1.0] - 2026-10-10

### Added
- Domain model for identities, credentials, resources, access grants, policies,
  alerts, tenants, users, API keys and connectors.
- Pluggable `Store` interface with in-memory and file-backed implementations.
- RS256 JWT authentication and `X-API-Key` authentication with argon2id
  password hashing and SHA-256 API-key hashing.
- RBAC (owner/admin/analyst/viewer) enforced per route.
- REST API (`/v1`) covering auth, tenants, users, API keys, identities,
  credentials, grants, resources, connectors, policies, alerts and stats.
- Connector framework with a deterministic `simulated` connector, a runner with
  external-reference resolution, and a per-tenant scheduler.
- AES-256-GCM secret box for connector secrets at rest.
- Cobra CLI (`serve`, `bootstrap`, `connector`, `version`).
- Bootstrap provisioning of the first tenant and owner user.
- Unit and integration tests for auth, store and API.

[Unreleased]: https://github.com/sentinel-iam/sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sentinel-iam/sentinel/releases/tag/v0.1.0

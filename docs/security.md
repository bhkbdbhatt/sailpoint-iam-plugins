# Sentinel Security

Threat model and hardening guidance for operating Sentinel. For the disclosure
process see [`SECURITY.md`](../SECURITY.md).

## Assets and trust boundaries

- **Data plane**: tenant-scoped identities, credentials metadata, grants,
  resources, alerts — in `<data>/sentinel.json` (file store).
- **Key material**: `jwt.key` (RSA) signs access tokens; `master.key` (AES-256)
  encrypts connector secrets. Both live in `SENTINEL_DATA_DIR` with `0600`
  permissions and must never be committed or logged.
- **External systems**: Sentinel stores connection credentials (e.g. AWS) in
  `ConnectorConfig.Secrets`, which are encrypted at rest and only decrypted in
  memory during a run.

## How Sentinel protects data

- **Passwords** — argon2id (memory/timing/parallelism-parameterized hashes);
  `VerifyPassword` rejects malformed or hostile parameters (empty salt/hash,
  zero params, >1 GiB memory) to prevent panic/OOM.
- **API keys** — issued as `snl_` plaintext shown once; stored as SHA-256 hash +
  prefix; revocable and expirable; can only be granted the issuer's own role
  (owners may mint any role).
- **Sessions** — RS256 JWTs with `iss`, `iat`, `exp`, `nbf` enforced and 30s
  leeway; TTL configurable (`SENTINEL_JWT_TTL`).
- **Connector secrets** — AES-256-GCM (`secrets.Box`), key stored separately
  from the store file.
- **Rate limiting** — login attempts limited per client IP and per email
  (in-memory; scales to a single instance).
- **Transport** — Sentinel serves plain HTTP by default. Terminate TLS in front
  and enforce the JWT/API-key auth.

## Access control (RBAC)

Every `/v1` route is gated by a permission; see the matrix in the README.
Tenant scoping is enforced at the store layer (cross-tenant reads return 404).

## Input validation & robustness

- All request bodies are decoded and validated (`model` validation rules).
- The file-store snapshot loader and `auth.VerifyPassword` are fuzz targets
  (`internal/store/fuzz_test.go`, `internal/auth/fuzz_test.go`).
- The OpenAPI spec is validated in CI; `/docs` is the only route with relaxed
  CSP (loads `swagger-ui-dist` from pinned `unpkg.com`), everything else uses
  the strict default policy.

## Hardening checklist for deployments

- [ ] Terminate TLS (reverse proxy / LB) and disable direct HTTP exposure.
- [ ] Set `SENTINEL_JWT_ISSUER` and a short `SENTINEL_JWT_TTL` (default 12h).
- [ ] Change all default/bootstrap credentials immediately.
- [ ] Protect `SENTINEL_DATA_DIR` (0600 owner-only); back it up including
  `master.key`/`jwt.key` (see `docs/operations.md`).
- [ ] Run the container non-root, read-only FS, drop capabilities.
- [ ] Scrape `/metrics` internally; don't expose to the internet.
- [ ] Pin container images / binaries by digest; use the SBOM produced by
  goreleaser for supply-chain review.
- [ ] Run connectors with least-privilege credentials (AWS: see
  `docs/connector-aws-iam.md`).
- [ ] Monitor login failures and run failures (see `docs/operations.md`).

## Known limitations (beta)

- Login rate limiting is in-memory (per instance), not a shared store.
- No external session revocation list; revoking means waiting for JWT expiry or
  rotating `jwt.key`.
- Multi-instance deployments are not yet supported.
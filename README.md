# Sentinel

**Sentinel** is an identity & access governance platform for the modern identity
landscape. It continuously discovers, normalises and analyses identities across
clouds and on-prem systems — humans, service accounts, workloads, API keys,
OAuth tokens, devices, certificates and **AI agents / MCP servers**.

It exposes a clean REST API over a pluggable storage layer, enriched with
risk scoring, ownership coverage, credential-expiry tracking and a connector
scheduler.

> Built with Go. Single static binary — or container — with no external services
> required to run.

---

## Table of contents

- [Highlights](#highlights)
- [Quick start](#quick-start)
- [CLI](#cli)
- [Authentication](#authentication)
- [Authorization (RBAC)](#authorization-rbac)
- [REST API](#rest-api)
- [Configuration](#configuration)
- [Connectors](#connectors)
- [Project layout](#project-layout)
- [Development](#development)
- [Architecture](#architecture)
- [Roadmap](#roadmap)

---

## Highlights

- **Unified identity graph** — one model for humans, workloads, service
  accounts, API keys, OAuth tokens, AI agents, MCP servers, devices,
  certificates and teams.
- **Discovery connectors** — pluggable `Connector` interface with a deterministic
  `simulated` connector for demos/tests and a **live AWS IAM** connector
  (users, roles, groups, access keys, policy attachments); Azure Entra is
  scaffolded.
- **Connector scheduler** — runs enabled connectors per tenant on an interval.
- **Graph-ready storage** — `Store` interface with an in-memory and a durable
  file-backed implementation; Neo4j is scaffolded.
- **Security first** — RS256 JWTs, argon2id password hashing, SHA-256 API keys,
  and AES-256-GCM encryption for connector secrets at rest.
- **Multi-tenant + RBAC** — tenant-scoped data with owner/admin/analyst/viewer
  roles enforced per route.
- **Operational visibility** — a single `Overview` endpoint aggregates risk
  buckets, credential expiry, grant counts and ownership coverage; Prometheus
  metrics on `/metrics`, plus liveness/readiness probes.
- **Documented API** — an embedded OpenAPI 3.1 spec (`/openapi.yaml`) with an
  interactive Swagger UI at `/docs`.

---

## Quick start

Requires **Go 1.27+**.

```bash
# 1. Build
go build -o bin/sentinel ./cmd/sentinel

# 2. Create the first tenant + owner (persisted to ./data/sentinel.json)
./bin/sentinel bootstrap \
  --slug acme --tenant Acme \
  --email owner@example.com --name Owner \
  --password supersecret123

# 3. Run the API + scheduler (defaults to the file store)
./bin/sentinel serve

# 4. Log in
curl -s localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@example.com","password":"supersecret123"}'
```

Windows PowerShell equivalent:

```powershell
go build -o bin\sentinel.exe ./cmd/sentinel
.\bin\sentinel.exe bootstrap --slug acme --tenant Acme `
  --email owner@example.com --name Owner --password supersecret123
.\bin\sentinel.exe serve
```

### Run with Docker (optional)

```bash
docker compose up --build        # builds sentinel:dev, serves on :8080
curl -s localhost:8080/healthz   # liveness probe
```

The container auto-bootstraps the tenant/owner from the
`SENTINEL_BOOTSTRAP_*` environment variables (see `docker-compose.yml`) and
persists state in the `sentinel-data` volume. Change the default credentials
before real use.

---

## CLI

| Command | Description |
| --- | --- |
| `sentinel serve` | Start the HTTP API server and (optionally) the connector scheduler. |
| `sentinel serve --bootstrap` | Same, but create the bootstrap tenant/owner first if missing. |
| `sentinel bootstrap` | Create the initial tenant and owner user (idempotent). |
| `sentinel connector list --tenant <id>` | List connector configurations for a tenant. |
| `sentinel connector run --tenant <id> --id <configID>` | Run one connector immediately. |
| `sentinel version` | Print version, commit and build date. |

Version metadata can be injected at build time:

```bash
go build -ldflags "-X github.com/sentinel-iam/sentinel/internal/cli.version=1.0.0" \
  -o bin/sentinel ./cmd/sentinel
```

---

## Authentication

Two mechanisms are supported and can be used interchangeably:

1. **Bearer JWT** — obtained from `POST /v1/auth/login`. RS256, issued by
   `SENTINEL_JWT_ISSUER`, TTL `SENTINEL_JWT_TTL`. The signing key is generated
   on first run and stored at `SENTINEL_JWT_KEY_PATH`.
2. **API key** — sent as `X-API-Key: snl_...`. Keys are SHA-256 hashed at rest
   and can expire or be revoked.

```
Authorization: Bearer <jwt>
X-API-Key: snl_<base64url>
```

---

## Authorization (RBAC)

Every route is guarded by a permission. Roles map to permission sets:

| Permission | owner | admin | analyst | viewer |
| --- | :---: | :---: | :---: | :---: |
| `tenants:read` | ✅ | ✅ | ✅ | |
| `tenants:write` | ✅ | | | |
| `users:read` | ✅ | ✅ | ✅ | |
| `users:write` | ✅ | ✅ | | |
| `apikeys:write` | ✅ | ✅ | | |
| `identities:read` | ✅ | ✅ | ✅ | ✅ |
| `identities:write` | ✅ | ✅ | | |
| `credentials:read` | ✅ | ✅ | ✅ | ✅ |
| `grants:read` | ✅ | ✅ | ✅ | ✅ |
| `resources:read` | ✅ | ✅ | ✅ | ✅ |
| `connectors:read` | ✅ | ✅ | ✅ | ✅ |
| `connectors:write` | ✅ | ✅ | | |
| `connectors:run` | ✅ | ✅ | ✅ | |
| `policies:read` | ✅ | ✅ | ✅ | ✅ |
| `policies:write` | ✅ | ✅ | | |
| `alerts:read` | ✅ | ✅ | ✅ | |
| `alerts:write` | ✅ | ✅ | ✅ | |
| `stats:read` | ✅ | ✅ | ✅ | ✅ |

Non-owners may only issue API keys carrying their own role; only owners may
issue a key with a different role.

---

## REST API

All endpoints are prefixed with `/v1`. Lists return
`{ "data": [...], "total": n, "limit": n, "offset": n }` and support
`?limit=&offset=`.

| Method | Path | Permission |
| --- | --- | --- |
| `POST` | `/auth/login` | public |
| `GET` | `/auth/me` | authenticated |
| `GET` `POST` | `/tenants` | `tenants:read` / `tenants:write` |
| `GET` | `/tenants/{id}` | `tenants:read` |
| `GET` `POST` | `/users` | `users:read` / `users:write` |
| `GET` `PUT` `DELETE` | `/users/{id}` | `users:read` / `users:write` |
| `GET` `POST` | `/apikeys` | `apikeys:write` |
| `DELETE` | `/apikeys/{id}` | `apikeys:write` |
| `GET` `POST` | `/identities` | `identities:read` / `identities:write` |
| `GET` `PUT` `DELETE` | `/identities/{id}` | `identities:read` / `identities:write` |
| `GET` | `/credentials` · `/credentials/{id}` | `credentials:read` |
| `GET` | `/grants` · `/grants/{id}` | `grants:read` |
| `GET` | `/resources` · `/resources/{id}` | `resources:read` |
| `GET` `POST` | `/connectors` | `connectors:read` / `connectors:write` |
| `GET` `PUT` `DELETE` | `/connectors/{id}` | `connectors:read` / `connectors:write` |
| `POST` | `/connectors/{id}/run` | `connectors:run` |
| `GET` | `/connectors/{id}/runs` | `connectors:read` |
| `GET` `POST` | `/policies` | `policies:read` / `policies:write` |
| `GET` `PUT` `DELETE` | `/policies/{id}` | `policies:read` / `policies:write` |
| `GET` `POST` | `/alerts` | `alerts:read` / `alerts:write` |
| `GET` `PATCH` `DELETE` | `/alerts/{id}` | `alerts:read` / `alerts:write` |
| `GET` | `/stats/overview` | `stats:read` |
| `GET` | `/healthz` | public |
| `GET` | `/readyz` | public |
| `GET` | `/metrics` | public |
| `GET` | `/openapi.yaml` | public |
| `GET` | `/docs` | public |

An interactive OpenAPI 3.1 reference (all request/response shapes, filters and
security schemes) is served at [`/docs`](http://localhost:8080/docs).

### Example: run a discovery

```bash
TOKEN=$(curl -s localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@example.com","password":"supersecret123"}' | jq -r .token)

# register the built-in simulated connector
CID=$(curl -s localhost:8080/v1/connectors -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"simulated","name":"demo","enabled":true}' | jq -r .id)

# run it
curl -s -X POST localhost:8080/v1/connectors/$CID/run -H "Authorization: Bearer $TOKEN" | jq

# governance overview
curl -s localhost:8080/v1/stats/overview -H "Authorization: Bearer $TOKEN" | jq
```

---

## Configuration

Everything is configured via environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_HTTP_ADDR` | `:8080` | Listen address. |
| `SENTINEL_DATA_DIR` | `./data` | Directory for the store, keys and metadata. |
| `SENTINEL_STORE` | `file` | `file`, `memory` (ephemeral) or `neo4j` (not implemented). |
| `SENTINEL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `SENTINEL_JWT_KEY_PATH` | `<data>/jwt.key` | RSA private key (generated if absent). |
| `SENTINEL_JWT_TTL` | `12h` | Access-token lifetime. |
| `SENTINEL_JWT_ISSUER` | `sentinel` | JWT `iss` claim. |
| `SENTINEL_MASTER_KEY_PATH` | `<data>/master.key` | AES-GCM key (generated if absent). |
| `SENTINEL_SCHEDULER_ENABLED` | `true` | Start the connector scheduler. |
| `SENTINEL_SCHEDULER_INTERVAL` | `5m` | Scheduler tick. |
| `SENTINEL_DISCOVERY_TIMEOUT` | `5m` | Per-run connector timeout. |
| `SENTINEL_BOOTSTRAP_SLUG` | `default` | Bootstrap tenant slug. |
| `SENTINEL_BOOTSTRAP_TENANT` | `Default` | Bootstrap tenant name. |
| `SENTINEL_BOOTSTRAP_EMAIL` | — | Bootstrap owner email (enables auto-seed on `serve`). |
| `SENTINEL_BOOTSTRAP_NAME` | `Owner` | Bootstrap owner display name. |
| `SENTINEL_BOOTSTRAP_PASSWORD` | — | Bootstrap owner password. |
| `SENTINEL_NEO4J_URI` / `_USER` / `_PASSWORD` | — | Reserved for the Neo4j backend. |

---

## Connectors

A connector implements:

```go
type Connector interface {
    Key() model.ConnectorKey
    Discover(ctx context.Context, tenantID string, cfg model.ConnectorConfig) (*Result, error)
}
```

A `Result` carries discovered `Identities`, `Credentials`, `AccessGrants` and
`Resources`. The `Runner` decrypts the connector's secrets, applies an external
reference resolver (so grants can reference resources/identities by their
source-system external id), upserts everything, and records a `ConnectorRun`
with counts and status.

| Key | Status | Notes |
| --- | --- | --- |
| `simulated` | ✅ default | Deterministic demo/test data; no external access. |
| `aws_iam` | ✅ implemented | Live AWS IAM discovery — see [docs/connector-aws-iam.md](docs/connector-aws-iam.md) for setup, least-privilege IAM policy and mapping. |
| `azure_entra` | ⏳ reserved | Returns "not implemented" until it lands. |

---

## Project layout

```
cmd/sentinel/            CLI entrypoint
internal/
  api/                   chi router, middleware, HTTP handlers
  auth/                  JWT, argon2id passwords, API keys, RBAC
  bootstrap/             first tenant + owner provisioning
  cli/                   cobra commands (serve, bootstrap, connector, version)
  config/                environment configuration
  connector/             connector interface, simulated, runner, scheduler
  model/                 domain types, validation, errors
  secrets/               AES-256-GCM secret box
  store/                 Store interface, memory + file implementations
```

---

## Development

```bash
go build ./...            # compile
go vet ./...              # static analysis
go test ./...             # unit + integration tests
gofmt -l .                # formatting check
go test -race ./...       # race detector
./scripts/coverage.sh coverage.out 70   # enforce the 70% overall coverage gate
go test -fuzz FuzzVerifyPassword -fuzztime 10s ./internal/auth/
go test -fuzz FuzzFileSnapshotLoad -fuzztime 10s ./internal/store/
```

Lint and static analysis use `golangci-lint` (see `.golangci.yml`); run
`golangci-lint run ./...`.

Tests cover password/JWT/API-key/RBAC primitives, store CRUD + file
persistence round-trips (including concurrent writes), connector runner,
scheduler, AWS IAM mocks, bootstrap idempotency, the full API end-to-end flow
(bootstrap → login → create data → run the simulated connector → overview),
RBAC enforcement, API-key lifecycle, rate limiting, and OpenAPI/Swagger
endpoints. Fuzz targets cover `auth.VerifyPassword` and the file-store snapshot
loader. A k6 load test for the login + `GET /identities` + `GET /stats/overview`
scenario lives in `load/`. Overall coverage is enforced at 70% (`./scripts/coverage.sh`).

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for component, sequence and data-model
diagrams (Mermaid).

---

## Roadmap

- [x] Live AWS IAM discovery connector.
- [ ] Neo4j graph store implementation.
- [ ] Live Azure Entra discovery connector (Microsoft Graph).
- [ ] Policy evaluation engine and alert generation.
- [ ] Password rotation and credential lifecycle automation.
- [ ] Agent-identity governance endpoints (autonomy levels, kill switch).

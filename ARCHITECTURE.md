# Sentinel — Architecture

This document describes the structure, runtime behaviour and data model of
Sentinel. All diagrams are [Mermaid](https://mermaid.js.org/) and render on
GitHub (and most Markdown viewers).

---

## 1. System context

Sentinel sits between external identity sources and the governance consumers
(analysts, security tooling, dashboards). It normalises everything into one
identity graph and exposes it over a REST API.

```mermaid
flowchart LR
    subgraph Sources["Identity sources"]
        AWS["AWS IAM"]
        AZ["Azure Entra ID"]
        SIM["Simulated"]
        MAN["Manual / API"]
    end

    subgraph Sentinel["Sentinel platform"]
        CONN["Connector runtime"]
        STORE["Store (memory / file / neo4j)"]
        API["REST API v1"]
        SCHED["Scheduler"]
    end

    subgraph Consumers["Consumers"]
        UI["Dashboards / UI"]
        CLI["sentinel CLI"]
        SEC["Security tooling"]
    end

    AWS --> CONN
    AZ --> CONN
    SIM --> CONN
    MAN --> API
    SCHED --> CONN
    CONN --> STORE
    API --> STORE
    STORE --> API
    API --> UI
    API --> SEC
    CLI --> STORE
    CLI --> API
```

---

## 2. Layered architecture

Sentinel is a single Go module (`github.com/sentinel-iam/sentinel`) with a
strict dependency direction: `api` and `connector` depend on `store`, `model`,
`auth`, `secrets`; the concrete store depends only on `model`.

```mermaid
flowchart TB
    subgraph Presentation
        CLI["internal/cli + cmd/sentinel"]
        HTTP["internal/api (chi handlers)"]
    end

    subgraph Application
        AUTHN["internal/auth (JWT, API key, RBAC)"]
        BOOT["internal/bootstrap"]
        CDISP["internal/connector (dispatch, runner, scheduler)"]
    end

    subgraph Domain
        MODEL["internal/model"]
        SECRETS["internal/secrets"]
        CFG["internal/config"]
    end

    subgraph Infrastructure
        MEM["store.Memory"]
        FILE["store.Memory + file persistence"]
        NEO["store.Neo4j (planned)"]
    end

    CLI --> HTTP
    CLI --> BOOT
    CLI --> CDISP
    HTTP --> AUTHN
    HTTP --> CDISP
    HTTP --> MODEL
    CDISP --> MODEL
    CDISP --> SECRETS
    BOOT --> AUTHN
    BOOT --> MODEL
    AUTHN --> MODEL
    HTTP --> MEM
    HTTP --> FILE
    CDISP --> MEM
    CDISP --> FILE
    MEM -. implements .-> STOREIF["store.Store interface"]
    FILE -. implements .-> STOREIF
    NEO -. implements .-> STOREIF
```

---

## 3. Module dependency graph

```mermaid
flowchart LR
    cmd["cmd/sentinel"] --> cli
    cli --> api
    cli --> config
    cli --> connector
    cli --> bootstrap
    cli --> auth
    cli --> secrets
    cli --> store

    api --> auth
    api --> connector
    api --> model
    api --> secrets
    api --> store

    connector --> model
    connector --> secrets
    connector --> store

    bootstrap --> auth
    bootstrap --> model
    bootstrap --> store

    auth --> model
    store --> model
```

No package imports `api` or `cli`, keeping the core reusable and testable.

---

## 4. Request lifecycle (authentication + RBAC)

Every `chi` request passes through recovery, logging, authentication and a
per-route permission guard before reaching a handler.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant MW as chi middleware
    participant A as authn middleware
    participant P as requirePerm
    participant H as Handler
    participant S as Store

    C->>MW: HTTP request
    MW->>MW: RequestID, RealIP, Recoverer, Logger
    MW->>A: next
    alt Authorization: Bearer <jwt>
        A->>A: JWTManager.Parse (RS256, issuer, exp)
    else X-API-Key: snl_...
        A->>S: APIKeys().GetByHash(sha256(key))
        S-->>A: key (role, tenant, revoked, expiry)
    end
    alt credentials invalid
        A-->>C: 401 unauthorized
    else valid
        A->>A: build principal {user, tenant, role, method}
        A->>P: next (context carries principal)
        alt role lacks permission
            P-->>C: 403 forbidden
        else allowed
            P->>H: next
            H->>S: tenant-scoped query/mutation
            S-->>H: data
            H-->>C: JSON response
        end
    end
```

---

## 5. Connector run lifecycle

A run can be triggered manually (`POST /connectors/{id}/run`), by the CLI, or by
the scheduler. The `Runner` owns orchestration and bookkeeping.

```mermaid
sequenceDiagram
    autonumber
    participant T as Trigger (API / CLI / Scheduler)
    participant R as connector.Runner
    participant S as Store
    participant B as secrets.Box
    participant K as Connector

    T->>R: Run(tenantID, configID, trigger)
    R->>S: Connectors().GetConfig(...)
    S-->>R: ConnectorConfig
    R->>S: Connectors().CreateRun(status=running)
    S-->>R: ConnectorRun

    R->>R: registry.Get(config.Key)
    R->>B: Decrypt(config.Secrets)  (AES-256-GCM)
    B-->>R: plaintext secrets

    R->>K: Discover(ctx+timeout, tenantID, cfg)
    alt discovery error
        K-->>R: error
        R->>S: UpdateRun(status=failed, error)
        R->>S: UpdateConfig(last_status=failed)
        R-->>T: run (failed)
    else success
        K-->>R: Result{identities, credentials, grants, resources}
        R->>S: Upsert identities (pass 1)
        R->>S: Resolve owner refs, re-upsert (pass 2)
        R->>S: Upsert resources
        R->>S: Upsert credentials (resolve identity refs)
        R->>S: Upsert grants (resolve identity + resource refs)
        R->>S: UpdateRun(status=succeeded, counts)
        R->>S: UpdateConfig(last_status=succeeded)
        R-->>T: run (succeeded)
    end
```

The external-reference resolver lets connectors express relationships by
source-system external id (e.g. `sim:role:billing-writer`) which the runner maps
to internal UUIDs after upserting the referenced records.

### AWS IAM mapping

The `aws_iam` connector (see `docs/connector-aws-iam.md`) maps AWS resources onto
the unified model:

| AWS resource | Sentinel model |
| --- | --- |
| IAM **user** | `Identity { human }` |
| IAM **role** | `Identity { workload }` |
| IAM **group** | `Identity { team }` |
| **access key** (active + last-used metadata) | `Credential { access_key }` |
| IAM **policy** attached to a user/role/group | `Resource` + `AccessGrant` (the policy as resource, the attachment as grant) |
| **account ID / MFA state** | identity attributes |

Pagination is handled via AWS SDK v2 `List*Pages`; per-account discovery uses a
read-only credential resolved through the standard AWS credential provider chain.

---

## 6. Data model

Core entities and their relationships. All records are tenant-scoped except
`Tenant` itself.

```mermaid
erDiagram
    TENANT ||--o{ USER : "has"
    TENANT ||--o{ IDENTITY : "owns"
    TENANT ||--o{ CREDENTIAL : "owns"
    TENANT ||--o{ RESOURCE : "owns"
    TENANT ||--o{ ACCESS_GRANT : "owns"
    TENANT ||--o{ POLICY : "owns"
    TENANT ||--o{ ALERT : "owns"
    TENANT ||--o{ CONNECTOR_CONFIG : "configures"
    USER ||--o{ API_KEY : "issues"
    IDENTITY ||--o{ CREDENTIAL : "holds"
    IDENTITY ||--o{ ACCESS_GRANT : "granted"
    IDENTITY ||--o| AGENT_IDENTITY : "extends"
    IDENTITY ||--o{ ALERT : "subject of"
    RESOURCE ||--o{ ACCESS_GRANT : "target of"
    POLICY ||--o{ ACCESS_GRANT : "governs"
    CONNECTOR_CONFIG ||--o{ CONNECTOR_RUN : "produces"

    TENANT {
        string id PK
        string name
        string slug
        string status
    }
    USER {
        string id PK
        string tenant_id FK
        string email
        string password_hash
        string role
        string status
    }
    API_KEY {
        string id PK
        string user_id FK
        string prefix
        string hash
        string role
        bool revoked
    }
    IDENTITY {
        string id PK
        string tenant_id FK
        string type
        string name
        string owner_id FK
        string source_system
        string external_id
        int risk_score
        string status
    }
    AGENT_IDENTITY {
        string id PK
        string identity_id FK
        int autonomy_level
        string owner_id FK
        int max_delegation_depth
        string kill_switch_status
    }
    CREDENTIAL {
        string id PK
        string identity_id FK
        string type
        datetime expires_at
        string rotation_schedule
        bool is_ephemeral
    }
    RESOURCE {
        string id PK
        string tenant_id FK
        string name
        string type
        string external_id
    }
    ACCESS_GRANT {
        string id PK
        string identity_id FK
        string resource_id FK
        string entitlement
        int usage_count_30d
    }
    POLICY {
        string id PK
        string tenant_id FK
        string name
        string engine
        string intent_level
        string status
    }
    ALERT {
        string id PK
        string tenant_id FK
        string identity_id FK
        string severity
        string status
    }
    CONNECTOR_CONFIG {
        string id PK
        string tenant_id FK
        string key
        bool enabled
        int interval_minutes
        map secrets
    }
    CONNECTOR_RUN {
        string id PK
        string connector_config_id FK
        string status
        int identities_found
        int credentials_found
        int grants_found
        int resources_found
    }
```

### Identity types

`human`, `workload`, `service_account`, `api_key`, `oauth_token`, `ai_agent`,
`mcp_server`, `device`, `certificate`, `team`.

### Credential types

`password`, `api_key`, `access_key`, `oauth_token`, `certificate`,
`service_account_key`, `ssh_key`, `federated`.

---

## 7. Store abstraction

One interface, multiple backends. The file backend reuses the in-memory
implementation and adds an atomic JSON persistence hook on every mutation.

```mermaid
classDiagram
    class Store {
        <<interface>>
        +Identities() IdentityStore
        +Credentials() CredentialStore
        +AccessGrants() AccessGrantStore
        +Resources() ResourceStore
        +Tenants() TenantStore
        +Users() UserStore
        +APIKeys() APIKeyStore
        +Connectors() ConnectorStore
        +Policies() PolicyStore
        +Alerts() AlertStore
        +Stats() StatsStore
        +Ping(ctx) error
        +Close() error
    }

    class Memory {
        -mu sync.RWMutex
        -path string
        -tenants Map
        -users Map
        -identities Map
        -connectors Map
        -policies Map
        -alerts Map
        +NewMemory() Memory
        +NewFile(path) Memory
        -persistLocked() error
        -snapshotLocked() fileSnapshot
        -rebuildIndexes()
    }

    class fileSnapshot {
        <<value object>>
        +Version int
        +maps of all entities
        +atomic write (temp -> 0600 -> rename)
    }

    Store <|.. Memory : realizes
    Memory ..> fileSnapshot : serialize / load
    note for Memory "NewMemory() = ephemeral\nNewFile(path) = durable JSON backend"
```

### Persistence guarantees

- **Atomic writes** — snapshot is marshalled to a temp file in the same
  directory, chmod `0600`, then `os.Rename`d over the target.
- **Durability on mutation** — every successful write operation persists the
  full snapshot before returning (errors propagate to the caller).
- **Index rebuild on load** — `identityExt`, `resourceExt`, `userEmail`,
  `apiKeyHash`, `tenantSlug` are derived from primary maps, so the on-disk
  format stays minimal.
- **Sensitive fields** — `password_hash`, API-key `hash`, and connector
  `secrets` are carried in dedicated snapshot records; connector secrets are
  always stored **encrypted** (the API encrypts before writing).

---

## 8. Security model

```mermaid
flowchart LR
    subgraph Secrets["Secret material"]
        PW["argon2id password hashes"]
        AK["SHA-256 API-key hashes"]
        JWTK["RSA-2048 JWT key (jwt.key, 0600)"]
        MK["AES-256 master key (master.key, 0600)"]
        CS["Connector secrets (AES-256-GCM)"]
    end

    PW --> STORE
    AK --> STORE
    CS --> STORE
    JWTK --> JWTM["JWTManager (RS256)"]
    MK --> BOX["secrets.Box (AES-GCM)"]
    BOX --> CS
```

- Passwords: **argon2id** (`m=64MiB, t=3, p=4`, 32-byte key).
- API keys: random 32 bytes, `snl_` prefix, **SHA-256** hash stored; compared by
  lookup, revoked/expiry enforced.
- JWTs: **RS256**, issuer + expiry validated, `alg` confusion guarded.
- Connector secrets: **AES-256-GCM** with a per-install key; ciphertext only on
  disk.
- RBAC: role→permission matrix enforced by middleware on every route.

---

## 9. Startup & runtime topology

```mermaid
flowchart TB
    subgraph Process["sentinel serve (single process)"]
        BOOT["config.Load + openStore + LoadOrCreate(keys)"]
        SRV["http.Server :8080"]
        SCHED["Scheduler goroutine (ticker)"]
        SIG["signal.NotifyContext (SIGINT/SIGTERM)"]
    end
    BOOT --> SRV
    BOOT --> SCHED
    SIG --> SRV
    SIG --> SCHED
    SRV --> |graceful shutdown| SIG
```

Graceful shutdown drains the HTTP server (10s) before exit; the scheduler stops
when the context is cancelled.

---

## 10. Extensibility

| Extension point | How |
| --- | --- |
| New identity source | Implement `connector.Connector`, register in `connector.Default()`. |
| New storage backend | Implement `store.Store`, select via `SENTINEL_STORE`. |
| New permission | Add a `Perm*` constant and wire it into `rolePermissions` and a route. |
| Policy engines | Populate `Policy.Engine`; the engine hook is reserved for evaluation. |
| Alert generation | Write to `Alerts()` from a future evaluation component. |

The `aws_iam` connector key is implemented and registered by default; the
`azure_entra` key remains reserved and returns a "not implemented" error until a
`Connector` is registered for it.

---

## 11. Operational endpoints

The HTTP server exposes a set of non-versioned endpoints for operations and
developer experience in addition to the versioned `/v1/*` API:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness probe — always 200 when the process is up. |
| `GET /readyz` | Readiness probe — 200 once wiring is complete. |
| `GET /metrics` | Prometheus text exposition format (global HTTP + internal counters). |
| `GET /openapi.yaml` | The canonical OpenAPI 3.1 specification for the `/v1` API. |
| `GET /docs` | Swagger UI (loaded from a pinned CDN) bound to `openapi.yaml`. |

The OpenAPI spec is embedded into the binary via `go:embed` and is the
source of truth for request/response shapes and query parameters; the automated
spec validation runs against it in CI. The `/docs` route relaxes the
Content-Security-Policy header enough to load the Swagger UI bundle; every other
route keeps the strict default policy.

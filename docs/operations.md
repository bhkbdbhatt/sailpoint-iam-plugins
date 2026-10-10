# Sentinel Operations Guide

Operational guidance for running Sentinel `v0.9.0-beta.1` (`SENTINEL_STORE=file`).

## Quick reference

| Concern | Value |
| --- | --- |
| API | `:8080` (`SENTINEL_HTTP_ADDR`, insecure by default — put TLS in front) |
| Liveness | `GET /healthz` |
| Readiness | `GET /readyz` |
| Metrics | `GET /metrics` (Prometheus text format) |
| API reference | `GET /openapi.yaml` · `GET /docs` (Swagger UI) |
| Data directory | `SENTINEL_DATA_DIR` (default `./data`) |
| Store | file-backed JSON at `<data>/sentinel.json` |
| Secrets | `<data>/master.key` (AES) · `<data>/jwt.key` (RSA) — generated on first boot |

## Starting and bootstrapping

```bash
sentinel bootstrap --tenant Acme --slug acme \
  --email owner@example.com --name Owner --password 'change-me'
SENTINEL_DATA_DIR=/var/lib/sentinel sentinel serve
```

Bootstrapping is idempotent. Alternatively set `SENTINEL_BOOTSTRAP_*` env vars
and `SENTINEL_BOOTSTRAP_EMAIL` so `serve` seeds the tenant/owner on first start
(used by the container image).

## Health checks

- `/healthz` — process liveness; returns 200 whenever the process is up.
- `/readyz` — readiness; 200 once server wiring completes.
- Use `/healthz` for container `HEALTHCHECK` / orchestrator liveness
  (`sentinel healthcheck --url http://127.0.0.1:8080/healthz`).

## Monitoring

`/metrics` exposes Prometheus counters/summaries (HTTP requests, login activity,
connector runs). Example scrape config:

```yaml
scrape_configs:
  - job_name: sentinel
    static_configs:
      - targets: ["127.0.0.1:8080"]
    metrics_path: /metrics
```

Watch for: elevated `login_failures`, connector run failures
(`connector_run_duration`), 5xx rates. A k6 load test for the
login + `/identities` + `/stats/overview` scenario ships in `load/`:

```bash
k6 run --vus 20 --duration 60s load/login-identities.js
# p95 latency gate (150ms) is a threshold — the run fails if exceeded.
```

## Backups and recovery

The whole state lives in `SENTINEL_DATA_DIR`. Back up the entire directory:

- `sentinel.json` — all tenant data (identities, grants, configs, users…).
- `master.key` — required to decrypt connector secrets on restore.
- `jwt.key` — required to validate existing API keys and (JWT) sessions.

Losing `master.key` or `jwt.key` invalidates secrets/sessions respectively.
Use atomic tooling (the store itself writes via temp-file + rename). Restore by
replacing the directory while the process is stopped, then restart.

## Scheduler and connectors

- Scheduler runs enabled connectors per tenant on
  `SENTINEL_SCHEDULER_INTERVAL` (default `5m`); disable with
  `SENTINEL_SCHEDULER_ENABLED=false`.
- Manual runs: `POST /v1/connectors/{id}/run` or `sentinel connector run`.
- AWS IAM: configure least-privilege credentials via the standard AWS
  credential chain (see `docs/connector-aws-iam.md`). Connector secrets are
  stored AES-256-GCM encrypted; rotate `master.key` only by decrypting and
  re-encrypting.

## Known limitations

- The file store keeps the full dataset in memory and writes it back on each
  mutation. It is appropriate for early beta / single-instance workloads.
  For scale, the Neo4j backend is planned (`SENTINEL_STORE=neo4j`).
- Multi-instance horizontal scaling is not supported yet — run a single
  Sentinel instance per data directory.
- The store file is single-writer: back it up while the process is stopped.

## Upgrade path

1. Stop Sentinel.
2. Back up `SENTINEL_DATA_DIR`.
3. Replace the binary (or pull the new image).
4. Start and check `/readyz` + `/metrics`.
5. Spot-check `GET /v1/stats/overview` counts match pre-upgrade values.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Login fails though password is right | pending failed-login lockout | Wait out the rate-limit window. |
| `/docs` blank | CSP/corporate proxy blocking unpkg CDN | Serve the Swagger bundle from your own mirror; allowlist `unpkg.com`. |
| AWS connector fails auth | missing/expired AWS credentials | Verify the credential chain and the documented least-privilege policy. |
| `secret not found` on restore | `master.key` not restored | Restore `master.key` alongside `sentinel.json`. |
| High latency on `/identities` | large dataset, in-memory filters | Paginate (`limit`/`offset`, filters); plan a move to Neo4j. |
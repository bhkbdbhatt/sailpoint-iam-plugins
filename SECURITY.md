# Security Policy

Sentinel handles identity metadata and, in production, credentials used to
discover external systems. Security is a first-class concern of this project.

## Supported versions

| Version | Supported |
| --- | --- |
| `v0.9.0-beta.1` | ✅ Beta |
| `v0.1.0` | ❌ |
| `< v0.1.0` | ❌ |

Once a 1.x line is released, the most recent minor receives security fixes.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report suspected vulnerabilities privately to the maintainers by email:

- **Primary**: `security@sentinel-iam.github.io` (or the address in the GitHub
  repository's security advisory metadata).
- **Faster**: use GitHub's private **Security Advisories** (`Security →
  Report a vulnerability`).

Include as much of the following as you can:

- Affected version(s) / commit(s) and how you got the binary.
- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal script or request is ideal).
- Whether it is publicly known (e.g., a CVE) and any exploit PoC.

We will acknowledge within **3 business days**, keep you updated on the
investigation, and work with you to coordinate disclosure. We credit
researchers in advisories unless anonymity is requested.

## Security posture

See `docs/security.md` for the full threat model and hardening guidance. In
short:

- **Transport**: run behind TLS terminating proxy; set
  `SENTINEL_HTTP_ADDR` accordingly. JWT `iat`/`exp`/`iss` are enforced.
- **Secrets at rest**: connector secrets are AES-256-GCM encrypted with a
  master key stored separately from the data store; API keys are SHA-256
  hashed; passwords are argon2id.
- **Access control**: tenant-scoped data + per-route RBAC
  (owner/admin/analyst/viewer), API keys restricted to the issuer's own role.
- **Abuse**: login rate limiting (per IP + per email) with lockout.
- **Supply chain**: reproducible Go builds (see `.goreleaser.yaml`), SBOM
  generation, `govulncheck` in CI, and pinned third-party dependencies.
- **Input handling**: all HTTP bodies and the file-store snapshot are
  fuzz-tested (`auth.VerifyPassword`, snapshot loader) and validated against
  `model` validation rules.

## Scope

In scope: the `sentinel` binary, its embedded OpenAPI spec, the Docker image,
and `internal/` packages.

Out of scope: the external systems Sentinel *connects to* (e.g. AWS), and
consumer infrastructure, except where Sentinel misconfigures them by default.

## Vulnerability disclosure timeline

1. Confirmation and triage — within 3 business days of receipt.
2. Fix preparation and regression tests.
3. Coordinated disclosure — typically 30 days after a fix is available; a CVE
   is requested where applicable.
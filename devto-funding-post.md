---
title: "Sentinel: open-source identity governance for the AI-agent era — and why I need your help"
published: false
description: "Sentinel is a single-binary identity & access governance platform in Go that treats AI agents, MCP servers, service accounts and API keys as first-class identities. Here's what's built, where it's going, and how you can fund it."
tags: opensource, go, security, ai
cover_image: ""
---

Every org I talk to has the same invisible problem: nobody can answer **"what identities exist across our systems, and what can each of them do?"** — especially now that the answer includes AI agents and MCP servers.

I'm building **Sentinel** to fix that, in the open. And I need your help to keep it independent.

## The problem: the identity surface exploded

A decade ago, "identity" meant humans in an HR system. Today it's:

- humans
- service accounts and workloads
- API keys and OAuth tokens
- access keys and certificates
- devices
- **AI agents and MCP servers** — brand new, and already over-privileged

This attack surface is scattered across clouds and on-prem tools. The commercial tools that map it cost six figures and lock your data in a black box. The open-source alternatives are either single-purpose scanners or half-finished prototypes.

I think identity — the data that tells you *who can do what* — is too important to be a closed black box.

## What Sentinel is

**Sentinel is a continuous identity & access governance platform** built in Go. It **discovers, normalises and analyses** identities across your systems and exposes one clean REST API over a pluggable storage layer.

One static binary. No external services required to run.

```bash
go build -o bin/sentinel ./cmd/sentinel
./bin/sentinel bootstrap --slug acme --tenant Acme \
  --email owner@example.com --name Owner --password supersecret123
./bin/sentinel serve
```

### What's already shipped (v0.9.0-beta.1)

This isn't a slide deck — the core is running and tested:

- **Unified identity graph** — humans, workloads, service accounts, API keys, OAuth tokens, **AI agents, MCP servers**, devices, certificates and teams in one model.
- **Discovery connectors** — a pluggable `Connector` interface with a deterministic `simulated` connector and a **live AWS IAM connector** (users, roles, groups, access keys, policy attachments). Azure Entra is scaffolded.
- **Connector scheduler** — runs enabled connectors per tenant on an interval.
- **Pluggable storage** — a `Store` interface with in-memory and durable file-backed backends. Neo4j is scaffolded.
- **Security first** — RS256 JWTs, argon2id passwords, SHA-256 API keys, and **AES-256-GCM encryption for connector secrets at rest**.
- **Multi-tenant + RBAC** — owner / admin / analyst / viewer, enforced per route.
- **Operational visibility** — a single `Overview` endpoint, Prometheus metrics on `/metrics`, plus liveness/readiness probes.
- **Documented API** — an embedded OpenAPI 3.1 spec at `/openapi.yaml` with Swagger UI at `/docs`.

It even runs as a container in one command:

```bash
docker compose up --build
```

The project is **Apache-2.0 licensed** — genuinely open, no open-core bait-and-switch.

## Why this matters

Governance tooling has a nasty failure mode: if you can't see an identity, you can't secure it, and if the tool that *can* see it is closed and expensive, most teams simply go without.

I want Sentinel to be the boring, trustworthy, self-hostable layer that answers:

- What identities exist?
- Who owns them? (ownership coverage is a first-class metric)
- What credentials are they holding, and which are expiring?
- What can they access, and is any of it actually being used?
- Which of these are **autonomous AI agents**, and how much can they do on their own?

That last point is what makes this urgent. Agents and MCP servers are being handed credentials faster than anyone is governing them. We need identity infrastructure that treats them as first-class citizens — **before** the first big agent-driven breach.

## Roadmap

The beta is real. Here's what funding unlocks next:

- [ ] **Neo4j graph store** — for scale and relationship queries beyond the file store.
- [ ] **Live Azure Entra connector** (Microsoft Graph).
- [ ] **Policy evaluation engine** + alert generation.
- [ ] **Password / credential rotation automation.**
- [ ] **Agent-identity governance** — autonomy levels, delegation depth, and a **kill switch** for runaway agents and MCP servers.
- [ ] SSO / OIDC login and a web UI.

## The ask

Sentinel is a nights-and-weekends project right now. Every hour is unpaid, and the roadmap above is the part that makes this genuinely useful in production — the graph store, the policy engine, and agent governance.

I'm not interested in slapping a paywall on the core. I want to keep it Apache-2.0 and self-hostable. That means the funding model has to be **sponsorship**, not licensing.

**If Sentinel is useful to you, please fund it.**

### How your money is used

- **☕ $5/mo — Supporter.** Keeps CI running (the matrix builds and tests on Linux, macOS and Windows) and the lights on.
- **💛 $25/mo — Backer.** Directly funds roadmap features — every dollar is time spent building connectors, the policy engine and agent governance.
- **💚 $100/mo — Partner.** Priority triage on your issues, and input into the roadmap. (Design partners get early beta access today.)
- **🏢 Custom — Sponsor org.** Named sponsorship, your logo in the README, and a direct line for connector requests. Great if you're actually running IAM and want to shape where this goes.

### Where to sponsor

- **GitHub Sponsors:** https://github.com/sponsors/bhkbdbhatt
- **Repo & releases:** https://github.com/bhkbdbhatt/sailpoint-iam-plugins

If you'd rather fund a **specific** item — say, "get the Azure Entra connector shipped" — reach out and we'll scope it together.

## Not able to sponsor? You can still help a lot

This part costs nothing and matters just as much:

- ⭐ **Star the repo** — it genuinely helps visibility.
- 🐛 **Try the beta and file issues** — reproduce steps and expected-vs-actual are gold.
- 🔌 **Write a connector** — the `Connector` interface is small; a new identity source is a great first contribution.
- 📣 **Share this post** with someone drowning in identity sprawl.
- 🔐 **Security folks:** the disclosure process is in `SECURITY.md` — please don't open public issues for vulnerabilities.

Contributing guide: [CONTRIBUTING.md](https://github.com/bhkbdbhatt/sailpoint-iam-plugins/blob/main/CONTRIBUTING.md).

## What you're really funding

Open infrastructure for a problem that's about to get much worse. Identity governance for the AI-agent era, built in public, owned by no one, usable by everyone.

If that's a future you want to exist, I'd love your support.

**→ Sponsor Sentinel: https://github.com/sponsors/bhkbdbhatt**

Thanks for reading. Questions, ideas, or a system you're desperate to connect? Drop them in the comments — I'll be here.

---

*Sentinel is a work-in-progress beta (`v0.9.0-beta.1`). Feedback, bug reports and contributions are all welcome.*

# Architecture Documentation — SecureApp

## Overview

SecureApp is a portfolio project demonstrating **Security Engineering in practice** — a user management system built with security integrated across all layers, not bolted on afterwards.

---

## Stack

| Layer | Technology | Security rationale |
|---|---|---|
| Backend | FastAPI + Python 3.12 | Strong typing, native validation via Pydantic |
| Database | PostgreSQL 16 | Row-Level Security, native UUID, JSONB for audit |
| Auth | JWT + bcrypt | Industry standard, bcrypt makes offline brute force impractical |
| Orchestration | Docker Compose | Network isolation, reproducibility |
| Pipeline | GitHub Actions | SAST, CVE check, secrets scan automated on every commit |

---

## Architecture Decision Records (ADRs)

### ADR-001: FastAPI instead of Django
**Context:** Backend framework selection.
**Decision:** FastAPI with strict typing via Pydantic.
**Consequence:** Input validation at the application boundary — invalid data never reaches business logic or the database.

### ADR-002: JWT with 15-minute expiration
**Context:** Stateless authentication strategy.
**Decision:** Access token of 15min + refresh token of 7 days with rotation.
**Consequence:** Limited exposure window if a token is intercepted. Refresh token rotation detects token theft on the next legitimate use.

### ADR-003: Row-Level Security in PostgreSQL
**Context:** Data access control.
**Decision:** RLS with `SET LOCAL` injecting context per transaction.
**Consequence:** Two independent lines of defense — application AND database enforce authorization. A bug in the application does not expose other users' data.

### ADR-004: Soft delete instead of physical DELETE
**Context:** User deletion flow.
**Decision:** `is_active = False` instead of `DELETE FROM users`.
**Consequence:** History preserved for forensic audit. Audit logs maintain reference to the user even after "deletion".

### ADR-005: Append-only audit log
**Context:** Action traceability.
**Decision:** Table with no UPDATE or DELETE routes in the API.
**Consequence:** Forensic evidence remains intact even if the application is compromised.

### ADR-006: Docker network isolation
**Context:** Service exposure.
**Decision:** `internal: true` network for the database — no external route.
**Consequence:** An attacker who compromises the application cannot connect directly to the database from outside the Docker environment.

---

## Real Engineering Challenges

These problems were encountered and solved during development. Each one produced a documented decision.

### Challenge 1 — Semgrep false positive on `dummy_hash`
**Problem:** Semgrep's `detected-bcrypt-hash` rule flagged the `dummy_hash` variable in `auth_service.py` as a hardcoded credential.
**Context:** The hash is intentional. It exists to prevent timing attacks — the `verify_password()` call must execute even when the user doesn't exist, so response time is identical for valid and invalid emails. Without it, an attacker can enumerate registered accounts by measuring response latency.
**Decision:** Added `.semgrepignore` with a technical comment explaining the security rationale. This approach documents intent rather than silently suppressing a tool warning.

### Challenge 2 — pip-audit dependency conflict in CI
**Problem:** `pip-audit` attempted to install all dependencies to resolve the dependency graph before auditing, triggering a version conflict on `starlette` in the GitHub Actions environment.
**Context:** FastAPI manages `starlette` as a transitive dependency — pinning it explicitly creates conflicts in isolated CI environments.
**Decision:** Migrated to `safety`, which reads `requirements.txt` directly without installing packages, avoiding the resolution step entirely.

### Challenge 3 — CSP blocking Swagger UI
**Problem:** The security headers middleware applied `Content-Security-Policy` to all routes, including `/docs`. Swagger UI loads inline scripts that `script-src 'self'` blocked.
**Decision:** Made CSP conditional — applied only in production. In development, Swagger UI is accessible without restriction. In production, the `/docs` route is disabled entirely.

### Challenge 4 — `MutableHeaders` API incompatibility
**Problem:** Starlette's `MutableHeaders` object does not implement `.pop()` like a standard Python dict, causing a runtime `AttributeError`.
**Decision:** Replaced `.pop()` calls with `try/except` blocks using `del response.headers["key"]`, which is the correct interface for `MutableHeaders`.

---

## NIST Cybersecurity Framework Mapping

| NIST Function | Controls implemented |
|---|---|
| **Identify** | STRIDE threat model, asset classification |
| **Protect** | bcrypt, JWT, RLS, RBAC, rate limit, security headers, HTTPS |
| **Detect** | Audit log with IP/user_agent, pipeline with SAST and CVE scan |
| **Respond** | Token revocation, user deactivation, logs for investigation |
| **Recover** | Soft delete preserves data, audit trail for event reconstruction |

---

## Authentication Flow

```
1. POST /auth/login
   → Pydantic validates input
   → Rate limit: 10/min per IP
   → bcrypt.verify (same time for invalid email — timing attack prevention)
   → Returns access_token (15min) + refresh_token (7 days)
   → Audit log: LOGIN SUCCESS / FAILURE

2. Authenticated request
   → Bearer token in Authorization header
   → verify_access_token: validates signature + expiration
   → SET LOCAL injects user_id and role into PostgreSQL session
   → RLS policies applied automatically by the database
   → Audit log records the action

3. POST /auth/refresh
   → SHA-256 of refresh token → lookup in database
   → Checks: not revoked, not expired
   → Revokes the used token (rotation)
   → Returns new token pair

4. POST /auth/logout
   → Revokes ALL refresh tokens for the user
   → Audit log: LOGOUT
```

---

## Quick Start

```bash
git clone https://github.com/AlanStacholski/SecureApp.git
cd SecureApp
cp .env.example .env
# Edit .env — generate SECRET_KEY with: openssl rand -hex 32
docker compose up --build
```

| Service | URL |
|---|---|
| Swagger UI | http://localhost:8000/docs |
| Health check | http://localhost:8000/health |
| Frontend | http://localhost:3000 |
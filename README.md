# SecureApp 🔐
### A Security Engineering Reference Architecture

> A user management system intentionally built simple — so the security architecture around it can speak for itself.

[![Security Pipeline](https://github.com/seu-usuario/secureapp/actions/workflows/security.yml/badge.svg)](https://github.com/seu-usuario/secureapp/actions)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)

---

## What this project demonstrates

This is not a tutorial project. Every decision here was made intentionally to demonstrate **Security Engineering thinking** — the ability to identify threats, design controls, and integrate security across all layers of a system.

| Layer | What was implemented | Why it matters |
|---|---|---|
| **Code** | Pydantic input validation, parameterized ORM queries, no hardcoded secrets | Prevents SQLi, XSS, and credential exposure |
| **Authentication** | JWT (15min) + refresh token rotation, bcrypt rounds=12 | Short attack window, theft detection via rotation |
| **Authorization** | RBAC via dependency injection, Row-Level Security in PostgreSQL | Two independent authorization layers |
| **Infrastructure** | Docker network isolation, non-root container user | Limits blast radius of a compromise |
| **Observability** | Append-only audit log with IP, user-agent, timestamp | Forensic evidence that can't be erased |
| **Pipeline** | SAST (Semgrep), secrets scan (Gitleaks), CVE check, container scan (Trivy) | Security integrated into the development workflow |
| **Documentation** | STRIDE Threat Model, ADRs, NIST CSF mapping | Shows architectural thinking, not just implementation |

---

## Architecture

```
[Browser] ──HTTPS──> [Frontend :3000]
                           │
                           ▼
                    [Backend :8000]  ← rate limit, security headers, CORS
                           │
                     internal network (no external route)
                           │
                           ▼
                    [PostgreSQL :5432]  ← Row-Level Security
```

**Two network zones:**
- `external`: Browser ↔ Frontend ↔ Backend
- `internal`: Backend ↔ PostgreSQL only (Docker `internal: true`)

---

## Security Decisions (ADRs)

| Decision | Choice | Security rationale |
|---|---|---|
| JWT expiration | 15 minutes | Limits damage window if token is intercepted |
| Refresh token storage | SHA-256 hash only | Database leak doesn't expose valid tokens |
| Refresh token rotation | One-time use | Stolen token detected when legitimate user refreshes |
| Password hashing | bcrypt, 12 rounds | ~300ms per hash — brute force impractical at scale |
| User IDs | UUID v4 | 2¹²² combinations — prevents enumeration |
| User deletion | Soft delete (`is_active=false`) | Preserves forensic trail in audit logs |
| Audit log | No UPDATE/DELETE routes | Evidence cannot be erased even if app is compromised |
| Container user | Non-root (`appuser`) | Limits privilege escalation if container is exploited |
| Database network | Docker `internal: true` | No external route to PostgreSQL — ever |

---

## Threat Model (STRIDE Summary)

| Threat | Attack vector | Control |
|---|---|---|
| **Spoofing** | Token replay | 15min expiration + refresh rotation |
| **Tampering** | SQL injection | SQLAlchemy ORM, parameterized queries |
| **Repudiation** | "I didn't do that" | Append-only audit log with user_id + IP |
| **Info Disclosure** | password_hash in API response | Pydantic response schema never includes it |
| **Denial of Service** | Login brute force | Rate limit: 10 req/min on /auth/login |
| **Elevation of Privilege** | User accesses admin routes | `require_admin` dependency + PostgreSQL RLS |

Full threat model: [THREAT_MODEL.md](./THREAT_MODEL.md)

---

## Tech Stack

- **Backend:** Python 3.12 + FastAPI + SQLAlchemy (async)
- **Database:** PostgreSQL 16 with Row-Level Security
- **Auth:** JWT + bcrypt + Refresh Token Rotation
- **Orchestration:** Docker Compose
- **Pipeline:** GitHub Actions — Semgrep, Gitleaks, pip-audit, Trivy

---

## Quick Start

**Prerequisites:** Docker Desktop installed and running.

```bash
# 1. Clone
git clone https://github.com/seu-usuario/secureapp.git
cd secureapp

# 2. Configure environment
cp .env.example .env
# Edit .env — generate SECRET_KEY with: openssl rand -hex 32

# 3. Start
docker compose up --build

# 4. Access
# Swagger UI:   http://localhost:8000/docs
# Health check: http://localhost:8000/health
# Frontend:     http://localhost:3000
```

---

## Testing the API

1. Open http://localhost:8000/docs
2. **Register** → `POST /auth/register`
3. **Login** → `POST /auth/login` — copy the `access_token`
4. Click **Authorize** (top right) and paste the token
5. Try `GET /users/me` — returns your profile
6. Try `GET /users/` as a regular user — returns `403 Forbidden` (RBAC working)
7. Try `POST /auth/login` 11 times — returns `429 Too Many Requests` (rate limit working)

---

## NIST Cybersecurity Framework Mapping

| Function | Controls implemented |
|---|---|
| **Identify** | STRIDE threat model, asset classification |
| **Protect** | bcrypt, JWT, RLS, RBAC, rate limit, security headers |
| **Detect** | Audit log with IP/user-agent, pipeline with SAST and CVE scan |
| **Respond** | Token revocation, user deactivation, audit trail for investigation |
| **Recover** | Soft delete preserves data, audit trail for event reconstruction |

---

## Author

**Alan Stacholski** — Security Engineer | Software Developer  
🌐 [stacholski.com.br](https://stacholski.com.br)  
💼 [LinkedIn](https://linkedin.com/in/seu-perfil)  
🐙 [GitHub](https://github.com/seu-usuario)
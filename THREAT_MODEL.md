# Threat Model — SecureApp
**Methodology:** STRIDE
**Date:** 2024
**Author:** Alan Stacholski

---

## 1. Scope and Assets

### Protected assets
| Asset | Classification | Impact if compromised |
|---|---|---|
| User passwords | Critical | Credential stuffing against other services |
| JWT tokens | High | Unauthorized API access |
| Personal data (email, name) | High | LGPD / GDPR violation |
| Audit logs | Medium | Loss of forensic evidence |
| Application secrets (.env) | Critical | Full system compromise |

### Actors
- **Authenticated user** — access to own profile only
- **Administrator** — full access via RBAC
- **External attacker** — no valid credentials
- **Internal attacker** — legitimate user with malicious intent

---

## 2. Data Flow Diagram

```
[Browser] ──HTTPS──> [Frontend :3000]
                           │
                           │ HTTP (Docker internal network)
                           ▼
                    [Backend :8000]
                           │
                     internal network
                     (no external route)
                           │
                           ▼
                    [PostgreSQL :5432]
```

**Trust zones:**
- `external`: Browser ↔ Frontend ↔ Backend
- `internal`: Backend ↔ PostgreSQL (isolated, no external route)

---

## 3. STRIDE Analysis

### S — Spoofing (Identity Forgery)

| Threat | Attack vector | Control implemented |
|---|---|---|
| Attacker uses stolen credentials | Login with another user's email/password | bcrypt rounds=12 makes offline brute force impractical |
| Expired token reuse | JWT replay attack | 15min expiration + `exp` claim verification |
| JWT forgery | Signing token with a weak key | SECRET_KEY >= 32 chars validated at startup (fail fast) |
| Session fixation | Reusing refresh token after logout | All tokens revoked on logout |

### T — Tampering (Data Manipulation)

| Threat | Attack vector | Control implemented |
|---|---|---|
| SQL Injection | Malicious input in routes | SQLAlchemy ORM with parameterized queries |
| JWT payload tampering | Modifying token claims | HMAC-SHA256 signature detects any alteration |
| Modifying another user's data | PUT /users/{id} without authorization | RBAC: only admin or resource owner |
| XSS injection | Input containing `<script>` | Pydantic sanitizes input + CSP header blocks execution |

### R — Repudiation

| Threat | Attack vector | Control implemented |
|---|---|---|
| User denies an action | "I didn't delete that" | Audit log with IP, user_agent, timestamp and user_id |
| Attacker erases traces | DELETE on audit_logs | Table has no delete route — append-only by design |

### I — Information Disclosure

| Threat | Attack vector | Control implemented |
|---|---|---|
| Leaking password_hash via API | GET /users returns hash | Pydantic response schema never includes password_hash |
| User enumeration | Different response time for invalid email | Timing attack prevention with dummy hash |
| Leaking stack trace on errors | Unhandled exception exposes internal code | FastAPI returns generic message in production |
| Leaking secrets via repository | .env committed to git | .gitignore + .env.example with no real values |
| Leaking Server/framework header | `Server: uvicorn` response header | Middleware removes headers that reveal the stack |

### D — Denial of Service

| Threat | Attack vector | Control implemented |
|---|---|---|
| Login brute force | 10,000 password attempts | Rate limit: 10 req/min per IP on /auth/login |
| Registration flood | Creating thousands of accounts | Rate limit: 5 req/min per IP on /auth/register |
| Database connection exhaustion | Too many simultaneous connections | Connection pool with limit (pool_size=10) |
| Oversized payload | 100MB request body | FastAPI enforces body size limit by default |

### E — Elevation of Privilege

| Threat | Attack vector | Control implemented |
|---|---|---|
| Regular user accessing admin routes | GET /users without role=admin | `require_admin` dependency on all admin routes |
| User editing another user | PUT /users/{other_id} | Check: only admin or resource owner allowed |
| Container running as root | Process with root privileges | Dockerfile: USER appuser (non-root) |
| Database accessible externally | Direct PostgreSQL connection | Docker `internal: true` network — no external route |
| RLS bypass via direct SQL | Query without SET LOCAL | No public user with unrestricted access to the database |

---

## 4. Residual Risks

| Risk | Likelihood | Impact | Future mitigation |
|---|---|---|---|
| SECRET_KEY compromise | Low | Critical | Periodic key rotation, HSM in production |
| Volumetric DDoS | Medium | High | CDN / WAF (Cloudflare) in production |
| Vulnerable dependency | High | Variable | Dependabot + Safety in pipeline |
| Malicious admin (insider threat) | Low | High | MFA for admins, alerts on critical actions |

---

## 5. Defense in Depth — Controls by Layer

```
Layer 1 — Network:        Docker internal network, database not exposed externally
Layer 2 — Application:    Rate limit, CORS, Security Headers, HTTPS
Layer 3 — Authentication: JWT 15min, bcrypt 12 rounds, refresh token rotation
Layer 4 — Authorization:  RBAC via dependency injection
Layer 5 — Data:           Pydantic validation, parameterized ORM, RLS in database
Layer 6 — Audit:          Append-only audit log, IP + user_agent + timestamp
Layer 7 — Pipeline:       Secrets scan, SAST, CVE check, container scan
```

**Principle:** if one layer fails, the others contain the damage.
# Threat Model — SecureApp
**Metodologia:** STRIDE  
**Data:** 2024  
**Autor:** Alan Stacholski  

---

## 1. Escopo e Assets

### Assets protegidos
| Asset | Classificação | Impacto se comprometido |
|---|---|---|
| Senhas dos usuários | Crítico | Credential stuffing em outros serviços |
| Tokens JWT | Alto | Acesso não autorizado à API |
| Dados pessoais (email, nome) | Alto | Violação de LGPD/GDPR |
| Audit logs | Médio | Perda de evidência forense |
| Segredos da aplicação (.env) | Crítico | Comprometimento total do sistema |

### Atores
- **Usuário autenticado** — acesso ao próprio perfil
- **Administrador** — acesso total via RBAC
- **Atacante externo** — sem credenciais válidas
- **Atacante interno** — usuário legítimo com intenção maliciosa

---

## 2. Diagrama de Fluxo de Dados

```
[Browser] ──HTTPS──> [Frontend :3000]
                           │
                           │ HTTP (rede interna Docker)
                           ▼
[Browser] ──HTTPS──> [Backend :8000]
                           │
                     rede interna
                     (sem acesso externo)
                           │
                           ▼
                    [PostgreSQL :5432]
```

**Zonas de confiança:**
- `external`: Browser ↔ Frontend ↔ Backend
- `internal`: Backend ↔ PostgreSQL (isolado, sem rota externa)

---

## 3. Análise STRIDE

### S — Spoofing (Falsificação de Identidade)

| Ameaça | Vetor | Controle implementado |
|---|---|---|
| Atacante usa credenciais roubadas | Login com email/senha de outro usuário | bcrypt rounds=12 dificulta brute force offline |
| Reutilização de token expirado | Replay de JWT antigo | Expiração de 15min + verificação de `exp` |
| Forge de JWT | Assinar token com chave fraca | SECRET_KEY >= 32 chars validada na inicialização |
| Session fixation | Reutilizar refresh token após logout | Revogação de todos os tokens no logout |

### T — Tampering (Adulteração)

| Ameaça | Vetor | Controle implementado |
|---|---|---|
| SQL Injection | Input malicioso nas rotas | SQLAlchemy ORM com queries parametrizadas |
| Adulteração de payload JWT | Modificar claims do token | Assinatura HMAC-SHA256 detecta qualquer alteração |
| Modificar dados de outro usuário | PUT /users/{id} sem autorização | RBAC: apenas admin ou dono do recurso |
| Injeção de scripts (XSS) | Input com `<script>` | Pydantic sanitiza input + CSP header bloqueia execução |

### R — Repudiation (Repúdio)

| Ameaça | Vetor | Controle implementado |
|---|---|---|
| Usuário nega ter feito uma ação | "Não fui eu que deletei" | Audit log com IP, user_agent, timestamp e user_id |
| Atacante apaga rastros | DELETE em audit_logs | Tabela sem rota de deleção — append-only por design |

### I — Information Disclosure (Divulgação de Informação)

| Ameaça | Vetor | Controle implementado |
|---|---|---|
| Vazar password_hash via API | GET /users retorna hash | Schema Pydantic nunca inclui password_hash no response |
| Enumerar usuários válidos | Tempo de resposta diferente para email inexistente | Timing attack prevention com dummy hash |
| Vazar stack trace em erros | Exceção não tratada expõe código interno | FastAPI retorna apenas mensagem genérica em produção |
| Vazar segredos via repositório | .env commitado no git | .gitignore + .env.example sem valores reais |
| Vazar Server/framework header | Header `Server: uvicorn` | Middleware remove headers que revelam stack |

### D — Denial of Service (Negação de Serviço)

| Ameaça | Vetor | Controle implementado |
|---|---|---|
| Brute force no login | 10.000 tentativas de senha | Rate limit: 10 req/min por IP no /auth/login |
| Flood de registro | Criar milhares de contas | Rate limit: 5 req/min por IP no /auth/register |
| Exaustão de conexões do banco | Muitas conexões simultâneas | Pool de conexões com limite (pool_size=10) |
| Payload gigante | Request body de 100MB | FastAPI limita body por padrão |

### E — Elevation of Privilege (Escalada de Privilégio)

| Ameaça | Vetor | Controle implementado |
|---|---|---|
| Usuário comum acessa rota admin | GET /users sem role=admin | Dependency `require_admin` em todas as rotas admin |
| Usuário edita outro usuário | PUT /users/{outro_id} | Verificação: só admin ou dono do recurso |
| Container como root | Processo rodando como root | Dockerfile: USER appuser (não-root) |
| Banco acessível externamente | Conexão direta ao PostgreSQL | Rede Docker `internal: true` — banco sem rota externa |
| Bypass de RLS via SQL direto | Query sem SET LOCAL | Banco sem usuário público com acesso irrestrito |

---

## 4. Riscos Residuais

| Risco | Probabilidade | Impacto | Mitigação futura |
|---|---|---|---|
| Comprometimento do SECRET_KEY | Baixa | Crítico | Rotação periódica de chaves, HSM em produção |
| DDoS volumétrico | Média | Alto | CDN / WAF (Cloudflare) em produção |
| Vulnerabilidade em dependência | Alta | Variável | Dependabot + pip-audit no pipeline |
| Insider threat (admin malicioso) | Baixa | Alto | MFA para admins, alertas em ações críticas |

---

## 5. Controles por Camada (Defense in Depth)

```
Camada 1 — Rede:      Docker network internal, sem exposição do banco
Camada 2 — Aplicação: Rate limit, CORS, Security Headers, HTTPS
Camada 3 — Autenticação: JWT 15min, bcrypt 12 rounds, refresh rotation
Camada 4 — Autorização: RBAC via dependency injection
Camada 5 — Dados: Pydantic validation, ORM parametrizado, RLS no banco
Camada 6 — Auditoria: Audit log append-only, IP + user_agent + timestamp
Camada 7 — Pipeline: Secrets scan, SAST, CVE check, container scan
```

**Princípio:** se uma camada falhar, as outras contêm o dano.
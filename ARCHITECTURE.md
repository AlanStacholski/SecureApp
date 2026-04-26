# Architecture Documentation — SecureApp

## Visão Geral

SecureApp é um projeto de portfólio demonstrando **Security Engineering na prática** — um sistema de gestão de usuários construído com segurança integrada em todas as camadas, não adicionada depois.

---

## Stack

| Camada | Tecnologia | Justificativa de segurança |
|---|---|---|
| Backend | FastAPI + Python 3.12 | Tipagem forte, validação nativa via Pydantic |
| Banco | PostgreSQL 16 | Row-Level Security, UUID nativo, JSONB para audit |
| Auth | JWT + bcrypt | Padrão de mercado, bcrypt dificulta brute force offline |
| Orquestração | Docker Compose | Isolamento de rede, reprodutibilidade |
| Pipeline | GitHub Actions | SAST, CVE check, secrets scan automatizados |

---

## Architecture Decision Records (ADRs)

### ADR-001: FastAPI em vez de Django
**Contexto:** Escolha do framework backend.  
**Decisão:** FastAPI com tipagem estrita via Pydantic.  
**Consequência:** Validação de input na borda da aplicação — dados inválidos nunca chegam à lógica de negócio ou ao banco.

### ADR-002: JWT com expiração de 15 minutos
**Contexto:** Estratégia de autenticação stateless.  
**Decisão:** Access token de 15min + refresh token de 7 dias com rotation.  
**Consequência:** Janela de exposição limitada se um token for interceptado. Refresh token rotation detecta roubo de token.

### ADR-003: Row-Level Security no PostgreSQL
**Contexto:** Controle de acesso aos dados.  
**Decisão:** RLS com `SET LOCAL` injetando contexto por transação.  
**Consequência:** Duas linhas de defesa independentes — aplicação E banco aplicam autorização. Um bug na aplicação não expõe dados de outros usuários.

### ADR-004: Soft delete em vez de DELETE físico
**Contexto:** Deleção de usuários.  
**Decisão:** `is_active = False` em vez de `DELETE FROM users`.  
**Consequência:** Histórico preservado para auditoria forense. Audit logs mantêm referência ao usuário mesmo após "deleção".

### ADR-005: Audit log append-only
**Contexto:** Rastreabilidade de ações.  
**Decisão:** Tabela sem rotas de UPDATE ou DELETE na API.  
**Consequência:** Evidência forense intacta mesmo se a aplicação for comprometida.

### ADR-006: Isolamento de rede no Docker
**Contexto:** Exposição de serviços.  
**Decisão:** Rede `internal: true` para o banco — sem rota externa.  
**Consequência:** Atacante que compromete a aplicação não consegue conectar diretamente ao banco de fora do ambiente Docker.

---

## Mapeamento NIST Cybersecurity Framework

| Função NIST | Controle implementado |
|---|---|
| **Identify** | Threat model STRIDE, classificação de assets |
| **Protect** | bcrypt, JWT, RLS, RBAC, rate limit, security headers, HTTPS |
| **Detect** | Audit log com IP/user_agent, pipeline com SAST e CVE scan |
| **Respond** | Revogação de tokens, desativação de usuário, logs para investigação |
| **Recover** | Soft delete preserva dados, audit trail para reconstrução de eventos |

---

## Fluxo de Autenticação

```
1. POST /auth/login
   → Pydantic valida input
   → Rate limit: 10/min por IP
   → bcrypt.verify (mesmo tempo para email inválido — timing attack prevention)
   → Retorna access_token (15min) + refresh_token (7 dias)
   → Audit log: LOGIN SUCCESS/FAILURE

2. Requisição autenticada
   → Bearer token no header Authorization
   → verify_access_token: valida assinatura + expiração
   → SET LOCAL injeta user_id e role no PostgreSQL
   → RLS aplica políticas automaticamente
   → Audit log registra a ação

3. POST /auth/refresh
   → SHA-256 do refresh token → busca no banco
   → Verifica: não revogado, não expirado
   → Revoga o token usado (rotation)
   → Retorna novo par de tokens

4. POST /auth/logout
   → Revoga TODOS os refresh tokens do usuário
   → Audit log: LOGOUT
```

---

## Como rodar

```bash
git clone https://github.com/seu-usuario/secureapp
cd secureapp
cp .env.example .env
# edite .env com suas senhas
docker compose up --build
```

- API: http://localhost:8000
- Swagger: http://localhost:8000/docs
- Health: http://localhost:8000/health
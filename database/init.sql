-- ============================================================
-- SecureApp — Schema com Row-Level Security (RLS)
-- ADR-003: segurança no nível do banco como segunda linha de defesa
-- ============================================================

-- Extensão para UUIDs (evita IDs sequenciais previsíveis)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- Tabela de usuários
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) UNIQUE NOT NULL,
    -- senha nunca armazenada em texto plano — apenas o hash bcrypt
    password_hash VARCHAR(255) NOT NULL,
    full_name     VARCHAR(255) NOT NULL,
    role          VARCHAR(50) NOT NULL DEFAULT 'user'
                  CHECK (role IN ('admin', 'user')),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Tabela de audit log (append-only — sem UPDATE ou DELETE)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(100) NOT NULL,   -- ex: LOGIN, CREATE_USER, DELETE_USER
    resource    VARCHAR(100),            -- ex: users, audit_logs
    resource_id UUID,                    -- id do recurso afetado
    ip_address  INET,
    user_agent  TEXT,
    status      VARCHAR(20) NOT NULL     -- SUCCESS, FAILURE
                CHECK (status IN ('SUCCESS', 'FAILURE')),
    detail      JSONB,                   -- contexto adicional sem dados sensíveis
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Tabela de refresh tokens (controle de sessão)
-- ============================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) NOT NULL UNIQUE,  -- hash do token, nunca o token real
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Índices para performance e segurança
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens(user_id);

-- ============================================================
-- Trigger para atualizar updated_at automaticamente
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================
-- Row-Level Security (RLS)
-- ADR-003: usuário comum só lê/edita o próprio registro
-- ============================================================

-- Habilita RLS nas tabelas sensíveis
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Política: admin vê tudo
CREATE POLICY admin_full_access ON users
    TO PUBLIC
    USING (
        current_setting('app.current_user_role', TRUE) = 'admin'
    );

-- Política: usuário comum só vê o próprio registro
CREATE POLICY user_own_record ON users
    TO PUBLIC
    USING (
        id::text = current_setting('app.current_user_id', TRUE)
    );

-- Política: audit logs só para admins
CREATE POLICY admin_audit_access ON audit_logs
    TO PUBLIC
    USING (
        current_setting('app.current_user_role', TRUE) = 'admin'
    );

-- Política: refresh tokens — cada usuário só vê os próprios
CREATE POLICY user_own_tokens ON refresh_tokens
    TO PUBLIC
    USING (
        user_id::text = current_setting('app.current_user_id', TRUE)
    );

-- ============================================================
-- Usuário admin inicial (senha: Admin@123456 — troque em produção)
-- A aplicação sobrescreve isso via variável de ambiente
-- ============================================================
INSERT INTO users (email, password_hash, full_name, role)
VALUES (
    'admin@secureapp.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iCte',
    'Admin Inicial',
    'admin'
) ON CONFLICT (email) DO NOTHING;
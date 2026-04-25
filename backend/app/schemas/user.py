import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
import re


# ============================================================
# Schemas de entrada (request) — validação rigorosa de input
# ============================================================

class UserCreate(BaseModel):
    email: EmailStr                   # valida formato de email automaticamente
    password: str
    full_name: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        """
        Decisão de segurança: senha fraca é rejeitada antes de chegar
        na camada de serviço. Validação na borda da aplicação.
        """
        errors = []
        if len(v) < 8:
            errors.append("mínimo 8 caracteres")
        if not re.search(r"[A-Z]", v):
            errors.append("pelo menos uma letra maiúscula")
        if not re.search(r"[a-z]", v):
            errors.append("pelo menos uma letra minúscula")
        if not re.search(r"\d", v):
            errors.append("pelo menos um número")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            errors.append("pelo menos um caractere especial")
        if errors:
            raise ValueError(f"Senha inválida: {', '.join(errors)}")
        return v

    @field_validator("full_name")
    @classmethod
    def full_name_sanitize(cls, v: str) -> str:
        # Remove espaços extras, limita tamanho
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Nome deve ter pelo menos 2 caracteres")
        if len(v) > 255:
            raise ValueError("Nome muito longo")
        # Permite apenas letras, espaços e hífens (sem HTML ou scripts)
        if not re.match(r"^[\w\s\-\.àáâãäåæçèéêëìíîïðñòóôõöùúûüýþÿÀ-Ö]+$", v):
            raise ValueError("Nome contém caracteres inválidos")
        return v


class UserUpdate(BaseModel):
    full_name: str | None = None
    is_active: bool | None = None

    @field_validator("full_name")
    @classmethod
    def full_name_sanitize(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Nome deve ter pelo menos 2 caracteres")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ============================================================
# Schemas de saída (response) — controle do que a API expõe
# ============================================================

class UserResponse(BaseModel):
    """
    Decisão de segurança: password_hash NUNCA aparece aqui.
    Mesmo que o dev esqueça de filtrar na rota, o schema impede
    que dados sensíveis vazem pela API.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int              # segundos — informa o client quando renovar


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID | None
    action: str
    resource: str | None
    status: str
    created_at: datetime
    # ip_address e user_agent omitidos na resposta — dados de infra,
    # não devem ser expostos via API pública


class MessageResponse(BaseModel):
    message: str
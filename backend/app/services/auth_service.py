import uuid
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from app.models.user import User, RefreshToken
from app.schemas.user import UserCreate, TokenResponse
from app.config import get_settings

settings = get_settings()

# Contexto bcrypt — work factor 12 (padrão seguro em 2024)
# Cada incremento dobra o tempo de hash — dificulta brute force
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: str, role: str) -> str:
    """
    Access token com expiração curta (15 min por padrão).
    Decisão de segurança: janela curta limita o dano
    se o token for interceptado.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": user_id,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),   # JWT ID único — permite revogação futura
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_access_token(token: str) -> dict:
    """
    Verifica assinatura, expiração e estrutura do token.
    Lança HTTPException em qualquer falha — nunca retorna dados parciais.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id = payload.get("sub")
        role = payload.get("role")
        if not user_id or not role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"user_id": user_id, "role": role}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _hash_refresh_token(token: str) -> str:
    """
    Hash SHA-256 do refresh token para armazenar no banco.
    Mesmo princípio das senhas — o banco nunca guarda o token real.
    """
    return hashlib.sha256(token.encode()).hexdigest()


async def register_user(db: AsyncSession, data: UserCreate) -> User:
    # Verifica se email já existe
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email já cadastrado",
        )

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        full_name=data.full_name,
        role="user",
    )
    db.add(user)
    await db.flush()   # gera o UUID sem commitar ainda
    return user


async def authenticate_user(
    db: AsyncSession, email: str, password: str
) -> User:
    """
    Decisão de segurança: mesmo tempo de resposta para email
    inexistente e senha errada. Evita user enumeration attack.
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # Verifica senha mesmo se usuário não existe (timing attack prevention)
    dummy_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iCte"  # nosemgrep: generic.secrets.security.detected-bcrypt-hash
    password_to_check = user.password_hash if user else dummy_hash
    is_valid = verify_password(password, password_to_check)

    if not user or not is_valid or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",   # mensagem genérica intencional
        )
    return user


async def create_tokens(db: AsyncSession, user: User) -> TokenResponse:
    """Cria access token + refresh token e persiste o hash no banco."""
    access_token = create_access_token(str(user.id), user.role)

    # Refresh token: string aleatória de 64 bytes — não é JWT
    raw_refresh = secrets.token_urlsafe(64)
    token_hash = _hash_refresh_token(raw_refresh)

    refresh = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        ),
    )
    db.add(refresh)

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,   # retorna o token real só aqui, nunca mais
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


async def refresh_access_token(
    db: AsyncSession, raw_refresh_token: str
) -> TokenResponse:
    """
    Troca um refresh token válido por novos tokens.
    Implementa refresh token rotation — cada uso gera um novo par.
    O token usado é revogado imediatamente (one-time use).
    """
    token_hash = _hash_refresh_token(raw_refresh_token)

    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    refresh_token = result.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido ou expirado",
        )

    # Revoga o token usado (rotation — impede reuso)
    refresh_token.revoked = True

    # Busca o usuário
    result = await db.execute(
        select(User).where(User.id == refresh_token.user_id)
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário inativo",
        )

    return await create_tokens(db, user)


async def revoke_all_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Logout — revoga todos os refresh tokens do usuário."""
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False,
        )
    )
    tokens = result.scalars().all()
    for token in tokens:
        token.revoked = True
import uuid
from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db, get_db_with_rls
from app.models.user import User
from app.schemas.user import UserResponse, UserUpdate, AuditLogResponse, MessageResponse
from app.services.auth_service import verify_access_token, hash_password
from app.services.audit_service import log_action, get_audit_logs, AuditAction
from app.middleware.rate_limit import limiter

router = APIRouter()


def require_admin(token_data: dict = Depends(verify_access_token)) -> dict:
    """
    Dependency de autorização — apenas admins acessam rotas protegidas.
    Separar autenticação (quem é você) de autorização (o que pode fazer)
    é um princípio fundamental de arquitetura de segurança.
    """
    if token_data["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso restrito a administradores",
        )
    return token_data


@router.get("/me", response_model=UserResponse)
async def get_me(
    request: Request,
    token_data: dict = Depends(verify_access_token),
    db: AsyncSession = Depends(get_db),
):
    """Retorna dados do usuário autenticado."""
    result = await db.execute(
        select(User).where(User.id == uuid.UUID(token_data["user_id"]))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    await log_action(
        db, AuditAction.VIEW_USER, "SUCCESS",
        request=request,
        user_id=user.id,
        resource="users", resource_id=user.id,
    )
    return user


@router.put("/me", response_model=UserResponse)
async def update_me(
    request: Request,
    data: UserUpdate,
    token_data: dict = Depends(verify_access_token),
    db: AsyncSession = Depends(get_db),
):
    """Usuário atualiza apenas seus próprios dados."""
    result = await db.execute(
        select(User).where(User.id == uuid.UUID(token_data["user_id"]))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    if data.full_name is not None:
        user.full_name = data.full_name

    await log_action(
        db, AuditAction.UPDATE_USER, "SUCCESS",
        request=request, user_id=user.id,
        resource="users", resource_id=user.id,
    )
    return user


# ============================================================
# Rotas admin — requerem role=admin
# ============================================================

@router.get("/", response_model=list[UserResponse])
@limiter.limit("30/minute")
async def list_users(
    request: Request,
    page: int = 1,
    page_size: int = 20,
    token_data: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Lista todos os usuários — apenas admin."""
    offset = (page - 1) * page_size
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).limit(page_size).offset(offset)
    )
    users = result.scalars().all()

    await log_action(
        db, AuditAction.LIST_USERS, "SUCCESS",
        request=request,
        user_id=uuid.UUID(token_data["user_id"]),
        detail={"page": page, "page_size": page_size},
    )
    return users


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID,
    request: Request,
    token_data: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Retorna um usuário específico — apenas admin."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    await log_action(
        db, AuditAction.VIEW_USER, "SUCCESS",
        request=request,
        user_id=uuid.UUID(token_data["user_id"]),
        resource="users", resource_id=user_id,
    )
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    data: UserUpdate,
    request: Request,
    token_data: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Atualiza qualquer usuário — apenas admin."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    if data.full_name is not None:
        user.full_name = data.full_name
    if data.is_active is not None:
        user.is_active = data.is_active

    await log_action(
        db, AuditAction.UPDATE_USER, "SUCCESS",
        request=request,
        user_id=uuid.UUID(token_data["user_id"]),
        resource="users", resource_id=user_id,
    )
    return user


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: uuid.UUID,
    request: Request,
    token_data: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Soft delete — desativa o usuário em vez de remover do banco.
    Decisão de segurança: manter histórico para auditoria forense.
    """
    # Admin não pode deletar a si mesmo
    if str(user_id) == token_data["user_id"]:
        raise HTTPException(
            status_code=400,
            detail="Administrador não pode desativar a própria conta",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user.is_active = False

    await log_action(
        db, AuditAction.DELETE_USER, "SUCCESS",
        request=request,
        user_id=uuid.UUID(token_data["user_id"]),
        resource="users", resource_id=user_id,
    )
    return {"message": "Usuário desativado com sucesso"}


@router.get("/admin/audit-logs", response_model=dict)
async def list_audit_logs(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    token_data: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Retorna audit logs paginados — apenas admin."""
    logs = await get_audit_logs(db, page=page, page_size=page_size)
    await log_action(
        db, AuditAction.VIEW_AUDIT_LOGS, "SUCCESS",
        request=request,
        user_id=uuid.UUID(token_data["user_id"]),
    )
    return logs
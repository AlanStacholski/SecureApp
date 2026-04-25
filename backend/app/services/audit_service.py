import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import Request
from app.models.user import AuditLog


# Ações auditadas — enum implícito via constantes
class AuditAction:
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    REGISTER = "REGISTER"
    REFRESH_TOKEN = "REFRESH_TOKEN"
    CREATE_USER = "CREATE_USER"
    UPDATE_USER = "UPDATE_USER"
    DELETE_USER = "DELETE_USER"
    VIEW_USER = "VIEW_USER"
    LIST_USERS = "LIST_USERS"
    VIEW_AUDIT_LOGS = "VIEW_AUDIT_LOGS"
    LOGIN_FAILED = "LOGIN_FAILED"


async def log_action(
    db: AsyncSession,
    action: str,
    status: str,                          # "SUCCESS" ou "FAILURE"
    request: Request | None = None,
    user_id: uuid.UUID | None = None,
    resource: str | None = None,
    resource_id: uuid.UUID | None = None,
    detail: dict | None = None,
) -> None:
    """
    Registra uma ação no audit log.

    Decisão de segurança:
    - IP e User-Agent são extraídos do request — nunca do corpo da requisição
      (evita que o cliente forge esses valores via JSON)
    - detail nunca deve conter senhas, tokens ou dados sensíveis
    - Erros no audit log são silenciosos — nunca quebram o fluxo principal
    """
    ip_address = None
    user_agent = None

    if request:
        # Respeita X-Forwarded-For se vier de proxy confiável
        forwarded = request.headers.get("X-Forwarded-For")
        ip_address = forwarded.split(",")[0].strip() if forwarded else str(
            request.client.host
        ) if request.client else None
        user_agent = request.headers.get("User-Agent")

    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            detail=detail,
        )
        db.add(log)
        # Não faz commit aqui — a transação é gerenciada pelo caller
        # Garante atomicidade: se a ação principal falhar, o log também não persiste
    except Exception:
        # Audit log nunca pode derrubar a aplicação
        pass


async def get_audit_logs(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    user_id: uuid.UUID | None = None,
    action: str | None = None,
) -> dict:
    """
    Retorna logs paginados com filtros opcionais.
    Paginação obrigatória — nunca retorna tudo de uma vez.
    """
    query = select(AuditLog).order_by(AuditLog.created_at.desc())

    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action == action)

    # Total para paginação
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    # Página atual
    offset = (page - 1) * page_size
    query = query.limit(page_size).offset(offset)
    result = await db.execute(query)
    logs = result.scalars().all()

    return {
        "items": logs,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }
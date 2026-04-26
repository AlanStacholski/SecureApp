from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.schemas.user import UserCreate, LoginRequest, RefreshRequest, TokenResponse, UserResponse, MessageResponse
from app.services import auth_service
from app.services.audit_service import log_action, AuditAction
from app.middleware.rate_limit import limiter

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=201)
@limiter.limit("5/minute")
async def register(
    request: Request,
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    user = await auth_service.register_user(db, data)
    await log_action(
        db, AuditAction.REGISTER, "SUCCESS",
        request=request, user_id=user.id,
        resource="users", resource_id=user.id,
    )
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(
    request: Request,
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        user = await auth_service.authenticate_user(db, data.email, data.password)
        tokens = await auth_service.create_tokens(db, user)
        await log_action(
            db, AuditAction.LOGIN, "SUCCESS",
            request=request, user_id=user.id,
        )
        return tokens
    except Exception as e:
        await log_action(
            db, AuditAction.LOGIN_FAILED, "FAILURE",
            request=request,
            detail={"email": data.email},
        )
        raise e


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
async def refresh(
    request: Request,
    data: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    tokens = await auth_service.refresh_access_token(db, data.refresh_token)
    await log_action(db, AuditAction.REFRESH_TOKEN, "SUCCESS", request=request)
    return tokens


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_data: dict = Depends(auth_service.verify_access_token),
):
    import uuid
    await auth_service.revoke_all_tokens(db, uuid.UUID(token_data["user_id"]))
    await log_action(
        db, AuditAction.LOGOUT, "SUCCESS",
        request=request,
        user_id=uuid.UUID(token_data["user_id"]),
    )
    return {"message": "Logout realizado com sucesso"}
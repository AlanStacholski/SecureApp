from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from app.config import get_settings
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.rate_limit import limiter, rate_limit_exceeded_handler
from app.routers import auth, users

settings = get_settings()

app = FastAPI(
    title="SecureApp",
    description="Reference Security Architecture — Portfolio",
    version="0.1.0",
    docs_url="/docs" if not settings.is_production else None,
    redoc_url=None,
)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# Security headers em todas as respostas
app.add_middleware(SecurityHeadersMiddleware)

# CORS — apenas origens explicitamente permitidas
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "environment": settings.ENVIRONMENT}


# Routers
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
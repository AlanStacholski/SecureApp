from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse

# Limiter global — usado nas rotas via decorator
limiter = Limiter(key_func=get_remote_address)


async def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    """
    Resposta padronizada para rate limit excedido.
    HTTP 429 Too Many Requests com header Retry-After.
    """
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Muitas requisições. Tente novamente em instantes.",
            "retry_after": "60"
        },
        headers={"Retry-After": "60"},
    )
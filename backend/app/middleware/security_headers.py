from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import get_settings

settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # MutableHeaders usa delete(), não pop()
        try:
            del response.headers["X-Powered-By"]
        except KeyError:
            pass
        try:
            del response.headers["Server"]
        except KeyError:
            pass

        # CSP só em produção — Swagger usa inline scripts em dev
        if settings.is_production:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self';"
            )

        return response
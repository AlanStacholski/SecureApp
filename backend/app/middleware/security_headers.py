from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Aplica headers de segurança em todas as respostas.

    Cada header tem uma função específica de defesa:
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Impede que o browser adivinhe o content-type (MIME sniffing)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Impede que a página seja carregada em iframes (clickjacking)
        response.headers["X-Frame-Options"] = "DENY"

        # Força HTTPS em browsers modernos por 1 ano
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Política de recursos — restringe de onde scripts/imagens podem vir
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )

        # Não envia o Referer para outros domínios (protege URLs internas)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 🔥 Correção aplicada aqui (sem mudar estrutura)
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]

        if "Server" in response.headers:
            del response.headers["Server"]

        return response
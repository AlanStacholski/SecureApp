FROM python:3.12-slim

# Decisão de segurança: nunca rodar como root
# Se a aplicação for comprometida, o atacante não tem privilégios de sistema
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Instala dependências antes de copiar o código
# (melhor cache do Docker — dependências mudam menos que o código)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY ./app ./app

# Transfere ownership para o usuário não-root
RUN chown -R appuser:appuser /app

USER appuser

# Expõe apenas a porta necessária
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
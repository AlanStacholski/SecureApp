# SecureApp 🔐

Sistema de gestão de usuários construído com segurança em todas as camadas — projeto de portfólio de Security Engineering.

---

## Como rodar

### Pré-requisitos
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado e rodando

### Passo a passo

**1. Clone o repositório**
```bash
git clone https://github.com/seu-usuario/secureapp.git
cd secureapp
```

**2. Configure as variáveis de ambiente**
```bash
cp .env.example .env
```
Abra o `.env` e preencha:
```env
POSTGRES_PASSWORD=SenhaForte@2024
SECRET_KEY=cole_aqui_o_resultado_do_comando_abaixo
```
Gere uma chave segura:
```powershell
# Windows PowerShell
-join ((1..32) | ForEach {'{0:X2}' -f (Get-Random -Max 256)})

# Linux/Mac
openssl rand -hex 32
```

**3. Suba o projeto**
```bash
docker compose up --build
```

**4. Acesse**
| Serviço | URL |
|---|---|
| API Swagger | http://localhost:8000/docs |
| Health check | http://localhost:8000/health |
| Frontend | http://localhost:3000 |

---

## Testando a API

1. Abra http://localhost:8000/docs
2. **Registre um usuário** → `POST /auth/register`
3. **Faça login** → `POST /auth/login` — copie o `access_token`
4. Clique em **Authorize** no canto superior direito e cole o token
5. Teste as rotas protegidas

---

## Parar o projeto
```bash
docker compose down
```

---

## Documentação completa
- [ARCHITECTURE.md](./ARCHITECTURE.md) — decisões de design (ADRs)
- [THREAT_MODEL.md](./THREAT_MODEL.md) — análise de ameaças STRIDE
- [README em inglês](./README.en.md)
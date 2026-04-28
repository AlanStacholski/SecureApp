from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from app.config import get_settings

settings = get_settings()

# Engine assíncrono com pool de conexões
engine = create_async_engine(
    settings.DATABASE_URL,connect_args={"ssl": False},
    echo=settings.ENVIRONMENT == "development",  # log de SQL só em dev
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,   # verifica conexão antes de usar (evita conexões mortas)
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db():
    """
    Dependency padrão — sessão sem contexto de usuário.
    Usada apenas para autenticação (login/registro),
    onde o RLS não se aplica ainda.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_db_with_rls(user_id: str, user_role: str):
    """
    Decisão arquitetural (ADR-003):
    Injeta o contexto do usuário autenticado na sessão do PostgreSQL.
    O banco usa essas configurações para aplicar as políticas de RLS.

    SET LOCAL garante que o contexto é válido apenas para
    a transação atual — nunca vaza entre requisições.
    """
    async with AsyncSessionLocal() as session:
        try:
            # Injeta contexto para o PostgreSQL aplicar RLS
            await session.execute(
                text("SET LOCAL app.current_user_id = :uid"),
                {"uid": user_id}
            )
            await session.execute(
                text("SET LOCAL app.current_user_role = :role"),
                {"role": user_role}
            )
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
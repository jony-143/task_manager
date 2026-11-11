from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from config import settings


DATABASE_URL = settings.DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    echo=False,
    pool_size=5,  # Number of persistent connections
    max_overflow=10,  # Number of extra temporary connections beyond pool_size
    pool_timeout=30,  # Maximum wait time for a connection from the pool
    pool_recycle=1800,  # Recycle connections after this many seconds
    pool_pre_ping=True,        # handles dead connections
    pool_reset_on_return="rollback",  # rollback open transactions on connection return
)

SessionLocal = sessionmaker(engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass

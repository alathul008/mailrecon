from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from app.core.config import get_settings

class Base(DeclarativeBase):
    pass

settings=get_settings()
engine=create_engine(settings.database_url.replace('+aiosqlite',''), future=True)
SessionLocal=sessionmaker(engine, expire_on_commit=False, class_=Session)

def get_db():
    with SessionLocal() as session:
        yield session

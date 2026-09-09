from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from app.core.config import get_settings

class Base(DeclarativeBase):
    pass

settings=get_settings()
engine=create_engine(settings.database_url.replace('+aiosqlite',''), future=True)

@event.listens_for(engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    if dbapi_connection.__class__.__module__.startswith("sqlite3"):
        cursor=dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal=sessionmaker(engine, expire_on_commit=False, class_=Session)

def get_db():
    with SessionLocal() as session:
        yield session

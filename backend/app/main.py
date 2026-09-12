from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.body_limit import RequestBodyLimitMiddleware
from app.core.config import get_settings
from app.api.routes import router
from app.api.correlations import router as correlation_router
from app.api.account_discovery import router as account_discovery_router
from app.api.public_web import router as public_web_router
from app.services.lifecycle import worker_loop
from app.services.schema import ensure_schema
import asyncio
import os

settings=get_settings()
MAX_REQUEST_BODY_SIZE = 1_048_576


@asynccontextmanager
async def lifespan(app:FastAPI):
    os.makedirs("data",exist_ok=True)
    ensure_schema()
    stop_event=asyncio.Event()
    worker=asyncio.create_task(worker_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        await worker

app=FastAPI(title="MailRecon API",version="1.0.0",description="Local-first defensive email intelligence platform",lifespan=lifespan)
app.add_middleware(RequestBodyLimitMiddleware, max_body_size=MAX_REQUEST_BODY_SIZE)
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],allow_credentials=True,allow_methods=["GET","POST","DELETE"],allow_headers=["*"])
app.include_router(router)
app.include_router(correlation_router)
app.include_router(account_discovery_router)
app.include_router(public_web_router)
if os.path.isdir("/app/frontend/dist"):
    app.mount("/",StaticFiles(directory="/app/frontend/dist",html=True),name="frontend")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:8000 http://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response

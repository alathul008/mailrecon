from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.core.config import get_settings
from app.db.session import engine, Base
from app.api.routes import router
import os

settings=get_settings()
@asynccontextmanager
async def lifespan(app:FastAPI):
    os.makedirs("data",exist_ok=True)
    Base.metadata.create_all(engine)
    yield

app=FastAPI(title="MailRecon API",version="1.0.0",description="Local-first defensive email intelligence platform",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],allow_credentials=True,allow_methods=["GET","POST","DELETE"],allow_headers=["*"])
app.include_router(router)
if os.path.isdir("/app/frontend/dist"):
    app.mount("/",StaticFiles(directory="/app/frontend/dist",html=True),name="frontend")


@app.middleware("http")
async def request_guards(request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 1_048_576:
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail":"Request body too large"}, status_code=413)
        except ValueError:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail":"Invalid Content-Length"}, status_code=400)
    return await call_next(request)

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:8000 http://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response

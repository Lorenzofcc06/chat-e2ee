from fastapi import FastAPI, Request
from .core.logger import log
from .core.config import settings
from .models.user import Base
from sqlalchemy import create_engine

# Inicialização do banco (apenas para scaffolding inicial)
engine = create_engine(settings.database_url)
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.app_name, version="1.0.0")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    
    response = await call_next(request)
    
    log.info("Request Processed", extra={"structured_data": {
        "who": "UNAUTHENTICATED",
        "what": "HTTP_REQUEST",
        "where": f"{client_ip} -> {request.method} {path}",
        "why": f"Status: {response.status_code}"
    }})
    return response

@app.get("/health")
def health_check():
    return {"status": "ok", "app": settings.app_name}

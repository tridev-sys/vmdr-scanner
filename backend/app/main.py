from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db import init_db
from app.routers import reports, scans, stats, targets, vulnerabilities, webhooks


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="VMDR API",
    version="1.0.0",
    description="Vulnerability management dashboard API backed by ProjectDiscovery Nuclei.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
)

api = APIRouter(prefix="/api")


@api.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


for module in (targets, vulnerabilities, scans, stats, webhooks, reports):
    api.include_router(module.router)
app.include_router(api)

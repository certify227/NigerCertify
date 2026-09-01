from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import get_settings
from app.core.database import Base, SessionLocal, engine
from app.services.seed import seed_database

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Tafiya API",
    description="Marketplace de covoiturage, taxi brousse et bus au Niger.",
    version="0.1.0",
    lifespan=lifespan,
)

origins = settings.cors_origin_list
if settings.app_env == "development":
    origins = list({*origins, "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173"})

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/")
def root():
    return {
        "app": settings.app_name,
        "message": "Tafiya API — voyageons ensemble au Niger",
        "docs": "/docs",
        "health": "/api/health",
    }
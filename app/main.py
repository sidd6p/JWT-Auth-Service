from fastapi import FastAPI
from app.auth import router as auth_router
from app.database import Base, engine

app = FastAPI(title="Auth REST API")

Base.metadata.create_all(bind=engine)

app.include_router(auth_router, prefix="/auth", tags=["Auth"])

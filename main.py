from fastapi import FastAPI

from config import settings
from routers import admin, auth, tasks, users

app = FastAPI(
    title=settings.TITLE,
    openapi_url="/openapi.json",
    dependencies=None,
)

# app.add_middleware()

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(tasks.router)
app.include_router(admin.router)

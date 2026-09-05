from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api import router


app = FastAPI(
    title="Firewall Project API",
    version="0.1.0",
    description="REST API for the Linux firewall project",
)


app.include_router(router, prefix="/api")


BASE_DIR = Path(__file__).resolve().parent.parent

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "web" / "static"),
    name="static",
)


@app.get("/")
def root():
    return FileResponse(
        BASE_DIR / "web" / "templates" / "index.html"
    )
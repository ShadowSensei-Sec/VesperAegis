from pathlib import Path
import threading

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from app.api import router
from app.auth_service import validate_session
from app.traffic.monitor import TrafficMonitor
from app.firewall.policy_manager import PolicyManager

app = FastAPI(
    title="API",
    version="0.1.0",
    description="REST API for the Linux",
)
def start_traffic_monitor():
    policy_manager = PolicyManager()
    interfaces = policy_manager.load_interfaces()

    monitor_interface = interfaces.get("lan")

    if not monitor_interface:
        print("[!] Traffic monitor disabled: LAN interface not configured.")
        return

    monitor = TrafficMonitor(monitor_interface)
    monitor.start()


@app.on_event("startup")
def startup_event():
    monitor_thread = threading.Thread(
        target=start_traffic_monitor,
        daemon=True,
    )
    monitor_thread.start()

app.include_router(router, prefix="/api")

@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    path = request.url.path

    public_paths = {
        "/login",
    }

    if path in public_paths or path.startswith("/static/"):
        return await call_next(request)

    if path.startswith("/api/auth/"):
        return await call_next(request)

    token = request.cookies.get("vesper_session")

    if not validate_session(token):
        if path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required."},
            )

        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    return await call_next(request)


BASE_DIR = Path(__file__).resolve().parent.parent

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "web" / "static"),
    name="static",
)


@app.get("/login")
def login_page():
    return FileResponse(BASE_DIR / "web" / "templates" / "login.html")


@app.get("/")
def root():
    return FileResponse(BASE_DIR / "web" / "templates" / "index.html")

@app.get("/rules")
def rules_page():
    return FileResponse(
        BASE_DIR / "web" / "templates" / "rules.html"
    )

@app.get("/logs")
def logs_page():
    return FileResponse(
        BASE_DIR / "web" / "templates" / "logs.html"
    )

@app.get("/traffic")
def traffic_page():
    return FileResponse(
        BASE_DIR / "web" / "templates" / "traffic.html"
    )

@app.get("/system")
def system_page():
    return FileResponse(
        BASE_DIR / "web" / "templates" / "system.html"
    )


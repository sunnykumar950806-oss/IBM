"""
MITRE ATT&CK Alert Mapper — FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.database import init_db, SessionLocal
from app.api import alerts, mitre, dashboard


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialise DB and seed sample data
    init_db()
    db = SessionLocal()
    try:
        from app.data.sample_data import seed_sample_data
        inserted = seed_sample_data(db)
        if inserted:
            print(f"[startup] Seeded {inserted} sample alerts.")
    finally:
        db.close()
    yield
    # Shutdown: nothing to clean up


app = FastAPI(
    title="MITRE ATT&CK Alert Mapper",
    description=(
        "A defensive cybersecurity tool that maps security alerts to "
        "MITRE ATT&CK tactics and techniques with investigation guidance."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(alerts.router)
app.include_router(mitre.router)
app.include_router(dashboard.router)

# ── Static files (frontend) ───────────────────────────────────────────────────
_STATIC_DIR = Path(__file__).parent.parent / "frontend" / "static"
_TEMPLATES_DIR = Path(__file__).parent.parent / "frontend" / "templates"

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ── Frontend page routes ──────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def serve_dashboard():
    return FileResponse(str(_TEMPLATES_DIR / "index.html"))


@app.get("/analyze", include_in_schema=False)
def serve_analyze():
    return FileResponse(str(_TEMPLATES_DIR / "analyze.html"))


@app.get("/history", include_in_schema=False)
def serve_history():
    return FileResponse(str(_TEMPLATES_DIR / "history.html"))


@app.get("/techniques", include_in_schema=False)
def serve_techniques():
    return FileResponse(str(_TEMPLATES_DIR / "techniques.html"))


@app.get("/alert/{alert_id}", include_in_schema=False)
def serve_alert_detail(alert_id: int):
    return FileResponse(str(_TEMPLATES_DIR / "alert_detail.html"))


@app.get("/about", include_in_schema=False)
def serve_about():
    return FileResponse(str(_TEMPLATES_DIR / "about.html"))

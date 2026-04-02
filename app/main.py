"""
AI Incident Analyzer — FastAPI application.

An AI-powered security incident analysis tool that classifies alerts,
extracts IOCs, and generates structured incident reports.
"""

import logging
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from app.api.analyze import router as analyze_router
from app.api.health import router as health_router
from app.api.history import router as history_router
from app.config import settings

# Logging setup
logging.basicConfig(
    level=logging.DEBUG if settings.APP_DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# App
app = FastAPI(
    title="AI Incident Analyzer",
    description="AI-powered security incident classification and IOC extraction",
    version="0.1.0",
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files & templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Register API routers
app.include_router(analyze_router)
app.include_router(health_router)
app.include_router(history_router)


# --- Page routes ---

@app.get("/")
async def index(request: Request):
    """Main analysis page."""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "api_configured": settings.is_api_configured,
    })


@app.on_event("startup")
async def startup():
    logger.info("=" * 60)
    logger.info("  AI Incident Analyzer v0.1.0")
    logger.info(f"  Environment: {settings.APP_ENV}")
    logger.info(f"  AI Model: {settings.AI_MODEL}")
    logger.info(f"  API Key: {'configured' if settings.is_api_configured else 'NOT SET'}")
    logger.info("=" * 60)

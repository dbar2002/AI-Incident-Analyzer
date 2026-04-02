"""Health check endpoint."""

from fastapi import APIRouter
from app.config import settings

router = APIRouter()


@router.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "api_configured": settings.is_api_configured,
        "environment": settings.APP_ENV,
    }

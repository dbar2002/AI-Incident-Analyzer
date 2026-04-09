"""
Incident history endpoints.

GET  /api/history          — list past incidents
GET  /api/history/{id}     — get full incident details
"""

from fastapi import APIRouter, HTTPException, Query
from app.services.database import get_incidents, get_incident_by_id, get_incident_count

router = APIRouter()


@router.get("/api/history")
async def list_incidents(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """List past incidents, most recent first."""
    incidents = get_incidents(limit=limit, offset=offset)
    total = get_incident_count()
    return {
        "incidents": incidents,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/api/history/{incident_id}")
async def get_incident(incident_id: str):
    """Retrieve full analysis result for a specific incident."""
    result = get_incident_by_id(incident_id)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result

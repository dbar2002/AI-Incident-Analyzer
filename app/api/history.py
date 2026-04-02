"""
Incident history endpoint — Phase 2.

Will provide access to past analysis results stored in SQLite.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/api/history")
async def get_history():
    """Placeholder — returns empty list until Phase 2."""
    return {"incidents": [], "message": "History feature coming in Phase 2"}

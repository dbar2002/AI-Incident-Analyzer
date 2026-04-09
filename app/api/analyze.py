"""
Analysis API endpoint — the core of the application.

POST /api/analyze
Accepts raw log/alert data, runs IOC extraction + AI classification,
returns structured incident analysis.
"""

import uuid
import time
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from app.models import AnalysisRequest, AnalysisResponse
from app.core.ioc_extractor import extract_iocs
from app.core.log_parser import parse_logs
from app.core.severity import calculate_severity_score
from app.services.ai_analyzer import classify_incident, generate_timeline, generate_playbook
from app.services.cve_lookup import lookup_cves
from app.core.cve_correlator import correlate_cves_to_iocs
from app.services.database import save_incident

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_logs(request: AnalysisRequest):
    """
    Analyze raw security log/alert data.

    Pipeline:
    1. Parse & normalize raw logs (deterministic)
    2. Extract IOCs via regex (deterministic)
    3. Calculate baseline severity score (deterministic)
    4. Send to AI for classification (non-deterministic)
    5. Return unified analysis response
    """
    if not request.raw_logs or not request.raw_logs.strip():
        raise HTTPException(status_code=400, detail="No log data provided")

    if len(request.raw_logs) > 50000:
        raise HTTPException(status_code=400, detail="Input exceeds 50,000 character limit")

    start_time = time.time()

    try:
        # Step 1: Parse log metadata
        parsed = parse_logs(request.raw_logs)
        log_metadata = parsed.to_dict()
        logger.info(f"Parsed {parsed.line_count} lines, format: {parsed.log_format}")

        # Step 2: Extract IOCs
        iocs = extract_iocs(request.raw_logs)
        logger.info(f"Extracted {iocs.total_count} IOCs")

        # Step 3: Baseline severity
        severity_info = calculate_severity_score(iocs, request.raw_logs)
        logger.info(f"Baseline severity: {severity_info['level']} (score: {severity_info['score']})")

        # Step 4: AI classification
        classification = await classify_incident(
            raw_logs=request.raw_logs,
            iocs=iocs,
            log_metadata=log_metadata,
        )

        # Step 5: CVE enrichment
        cve_details = []
        cve_correlations = None
        if iocs.cves:
            cve_ids = [cve.value for cve in iocs.cves]
            logger.info(f"Looking up {len(cve_ids)} CVE(s): {', '.join(cve_ids)}")
            cve_details = await lookup_cves(cve_ids)
            logger.info(f"Enriched {len(cve_details)} CVE(s)")

        # Step 6: CVE-IOC correlation
        if cve_details:
            cve_correlations = correlate_cves_to_iocs(cve_details, iocs, request.raw_logs)
            logger.info(f"CVE-IOC correlations: {cve_correlations.count}")

        # Step 7: Generate incident timeline
        timeline = await generate_timeline(
            raw_logs=request.raw_logs,
            classification=classification,
            log_metadata=log_metadata,
        )
        logger.info(f"Timeline: {len(timeline.events)} events")

        # Step 8: Generate response playbook
        playbook = await generate_playbook(
            classification=classification,
            timeline=timeline,
            iocs=iocs,
        )
        logger.info(f"Playbook: {len(playbook.steps)} steps")

        # Step 9: Build response
        duration_ms = int((time.time() - start_time) * 1000)

        response = AnalysisResponse(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            classification=classification,
            iocs=iocs,
            cve_details=cve_details,
            cve_correlations=cve_correlations,
            timeline=timeline,
            playbook=playbook,
            raw_input=request.raw_logs[:2000],
            analysis_duration_ms=duration_ms,
        )

        logger.info(
            f"Analysis complete in {duration_ms}ms — "
            f"type={classification.incident_type}, "
            f"severity={classification.severity}"
        )

        # Step 10: Save to history database
        save_incident(response.model_dump())

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Analysis pipeline failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

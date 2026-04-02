"""Integration tests for API endpoints."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_analyze_empty_input():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/analyze", json={"raw_logs": ""})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_analyze_returns_results():
    sample = "Failed password for admin from 203.0.113.42 port 22 ssh2"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/analyze", json={"raw_logs": sample})
    assert resp.status_code == 200
    data = resp.json()
    assert "classification" in data
    assert "iocs" in data
    assert data["iocs"]["ip_addresses"]  # should find the IP


@pytest.mark.asyncio
async def test_analyze_extracts_iocs():
    sample = """
    Connection from 185.234.72.19 to internal server.
    Downloaded malware.exe with hash d41d8cd98f00b204e9800998ecf8427e.
    Email from attacker@evil.com contained CVE-2024-21413.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/analyze", json={"raw_logs": sample})
    assert resp.status_code == 200
    data = resp.json()
    iocs = data["iocs"]
    assert len(iocs["ip_addresses"]) >= 1
    assert len(iocs["hashes"]) >= 1
    assert len(iocs["emails"]) >= 1
    assert len(iocs["cves"]) >= 1

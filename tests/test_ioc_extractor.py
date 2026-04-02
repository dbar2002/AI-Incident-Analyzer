"""Tests for IOC extraction logic."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.ioc_extractor import extract_iocs


class TestIPExtraction:
    def test_extracts_ipv4(self):
        text = "Connection from 192.168.1.100 to 10.0.0.1"
        iocs = extract_iocs(text)
        ips = [i.value for i in iocs.ip_addresses]
        assert "192.168.1.100" in ips
        assert "10.0.0.1" in ips

    def test_classifies_private_ip(self):
        text = "Source: 192.168.1.100"
        iocs = extract_iocs(text)
        assert iocs.ip_addresses[0].context == "Internal/private IP address"

    def test_classifies_external_ip(self):
        text = "Source: 203.0.113.42"
        iocs = extract_iocs(text)
        assert iocs.ip_addresses[0].context == "External IP address"

    def test_deduplicates_ips(self):
        text = "203.0.113.42 attacked 203.0.113.42 again"
        iocs = extract_iocs(text)
        assert len(iocs.ip_addresses) == 1


class TestHashExtraction:
    def test_extracts_sha256(self):
        text = "SHA256: 3a7b9f2e8d1c4b6a5e0f7d8c9b2a1e3f4d5c6b7a8e9f0d1c2b3a4e5f6d7c8b9a"
        iocs = extract_iocs(text)
        assert len(iocs.hashes) == 1
        assert iocs.hashes[0].type == "hash_sha256"

    def test_extracts_md5(self):
        text = "MD5: d41d8cd98f00b204e9800998ecf8427e"
        iocs = extract_iocs(text)
        assert len(iocs.hashes) == 1
        assert iocs.hashes[0].type == "hash_md5"

    def test_sha256_not_duplicated_as_md5(self):
        text = "Hash: 3a7b9f2e8d1c4b6a5e0f7d8c9b2a1e3f4d5c6b7a8e9f0d1c2b3a4e5f6d7c8b9a"
        iocs = extract_iocs(text)
        types = [h.type for h in iocs.hashes]
        assert "hash_md5" not in types


class TestURLExtraction:
    def test_extracts_defanged_url(self):
        text = "URL: hxxps://evil[.]com/payload"
        iocs = extract_iocs(text)
        assert len(iocs.urls) >= 1

    def test_extracts_normal_url(self):
        text = "Downloaded from https://malware-host.com/file.exe"
        iocs = extract_iocs(text)
        assert len(iocs.urls) == 1


class TestEmailExtraction:
    def test_extracts_emails(self):
        text = "From: attacker@evil.com to victim@company.com"
        iocs = extract_iocs(text)
        emails = [e.value for e in iocs.emails]
        assert "attacker@evil.com" in emails
        assert "victim@company.com" in emails


class TestFilenameExtraction:
    def test_extracts_exe(self):
        text = "Downloaded payload.exe to temp folder"
        iocs = extract_iocs(text)
        assert len(iocs.filenames) == 1
        assert iocs.filenames[0].value == "payload.exe"

    def test_extracts_double_extension(self):
        text = "Attachment: invoice.pdf.exe"
        iocs = extract_iocs(text)
        fnames = [f.value for f in iocs.filenames]
        assert any("pdf.exe" in f for f in fnames)


class TestCVEExtraction:
    def test_extracts_cve(self):
        text = "Exploited CVE-2024-21413 for initial access"
        iocs = extract_iocs(text)
        assert len(iocs.cves) == 1
        assert iocs.cves[0].value == "CVE-2024-21413"


class TestTotalCount:
    def test_total_count(self):
        text = """
        IP: 203.0.113.42
        Email: test@evil.com
        Hash: d41d8cd98f00b204e9800998ecf8427e
        CVE-2024-21413
        File: backdoor.exe
        """
        iocs = extract_iocs(text)
        assert iocs.total_count >= 4

"""Tests for AIReportGenerator — AI report generation with mocked LLM."""

import json
import pytest
from datetime import UTC, datetime
from unittest.mock import MagicMock

from app.models.ai_schemas import LLMResponse, ProviderType
from app.models.schemas import (
    Asset,
    AssetType,
    ParsedProgram,
    Report,
    SeverityLevel,
    Vulnerability,
)
from app.services.ai.ai_report_generator import AIReportGenerator


def _make_vuln():
    return Vulnerability(
        id="vuln-1",
        scan_id="scan-1",
        program_id="prog-1",
        vulnerability_type="sql_injection",
        severity=SeverityLevel.CRITICAL,
        description="SQL injection in login form",
        steps_to_reproduce="1. Go to /login\n2. Enter ' OR 1=1 --",
        evidence="All users returned",
        affected_asset=Asset(id="a1", name="Web App", asset_type=AssetType.WEB_APPLICATION, target="https://example.com"),
        impact_assessment="Full database access",
        remediation="Use parameterized queries",
        status="new",
        created_at=datetime.now(UTC),
    )


def _make_program():
    return ParsedProgram(
        id="prog-1",
        name="Test Program",
        platform="hackerone",
        assets=[],
        rules=[],
        reward_tiers=[],
        disclosure_requirements="Follow responsible disclosure",
        raw_text="",
        created_at=datetime.now(UTC),
    )


def _mock_llm(content: str):
    mgr = MagicMock()
    mgr.complete_with_pro.return_value = LLMResponse(
        content=content, model="deepseek-v4-pro", usage={}, provider=ProviderType.DEEPSEEK
    )
    return mgr


class TestGenerate:
    def test_generates_complete_report(self):
        response = json.dumps({
            "description": "SQL injection vulnerability in the login form",
            "steps_to_reproduce": "1. Navigate to /login\n2. Enter payload",
            "proof_of_concept": "curl -X POST ...",
            "impact": "Full database compromise",
            "remediation": "Use parameterized queries",
        })
        gen = AIReportGenerator(_mock_llm(response))
        report = gen.generate(_make_vuln(), _make_program())
        assert isinstance(report, Report)
        assert report.description != ""
        assert report.steps_to_reproduce != ""
        assert report.proof_of_concept != ""
        assert report.impact != ""
        assert report.remediation != ""
        assert report.vulnerability_id == "vuln-1"
        assert report.program_id == "prog-1"

    def test_fallback_on_llm_error(self):
        mgr = MagicMock()
        mgr.complete_with_pro.side_effect = Exception("LLM down")
        gen = AIReportGenerator(mgr)
        report = gen.generate(_make_vuln(), _make_program())
        assert isinstance(report, Report)
        assert report.description != ""

    def test_report_title_includes_severity(self):
        response = json.dumps({
            "description": "desc",
            "steps_to_reproduce": "steps",
            "proof_of_concept": "poc",
            "impact": "impact",
            "remediation": "fix",
        })
        gen = AIReportGenerator(_mock_llm(response))
        report = gen.generate(_make_vuln(), _make_program())
        assert "CRITICAL" in report.title


class TestImprove:
    def test_improves_report(self):
        original = Report(
            id="r1", vulnerability_id="v1", program_id="p1",
            title="Test", description="Old desc",
            steps_to_reproduce="Old steps", proof_of_concept="Old poc",
            impact="Old impact", severity=SeverityLevel.HIGH,
            remediation="Old fix", format_version="1.0",
            created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
        )
        response = json.dumps({
            "description": "Improved description",
            "steps_to_reproduce": "Improved steps",
            "proof_of_concept": "Improved poc",
            "impact": "Improved impact",
            "remediation": "Improved fix",
        })
        gen = AIReportGenerator(_mock_llm(response))
        improved = gen.improve(original, "Add more details")
        assert improved.description == "Improved description"
        assert improved.id == original.id

    def test_improve_fallback_returns_original(self):
        original = Report(
            id="r1", vulnerability_id="v1", program_id="p1",
            title="Test", description="desc",
            steps_to_reproduce="steps", proof_of_concept="poc",
            impact="impact", severity=SeverityLevel.HIGH,
            remediation="fix", format_version="1.0",
            created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
        )
        mgr = MagicMock()
        mgr.complete_with_pro.side_effect = Exception("LLM down")
        gen = AIReportGenerator(mgr)
        result = gen.improve(original, "improve it")
        assert result.description == original.description


class TestFallbackGenerate:
    def test_uses_template_generator(self):
        gen = AIReportGenerator(MagicMock())
        report = gen.fallback_generate(_make_vuln(), _make_program())
        assert isinstance(report, Report)
        assert "sql_injection" in report.title.lower() or "SQL" in report.title

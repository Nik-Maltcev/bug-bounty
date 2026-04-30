"""Tests for FindingAnalyzer — finding triage with mocked LLM."""

import json
import pytest
from unittest.mock import MagicMock

from app.models.ai_schemas import (
    FindingAnalysis,
    LLMResponse,
    ProviderType,
    SessionContext,
)
from app.models.schemas import RawFinding, SeverityLevel
from app.services.ai.finding_analyzer import FindingAnalyzer


def _make_finding():
    return RawFinding(
        vulnerability_type="sql_injection",
        description="SQL injection in login form parameter 'username'",
        evidence="' OR 1=1 -- returned all users",
        affected_asset_id="asset-1",
        raw_data={},
    )


def _make_context():
    return SessionContext(
        program_id="prog-1",
        program_name="Test Program",
        rules=[{"id": "R1", "description": "SQL testing allowed", "is_allowed": True, "category": "testing"}],
    )


def _mock_llm(content: str):
    mgr = MagicMock()
    mgr.complete.return_value = LLMResponse(
        content=content, model="test", usage={}, provider=ProviderType.DEEPSEEK
    )
    return mgr


class TestAnalyze:
    def test_real_vulnerability(self):
        response = json.dumps({
            "is_real_vulnerability": True,
            "confidence": 0.95,
            "severity": "critical",
            "exploitability": "easy",
            "reasoning": "Classic SQL injection with evidence of data extraction",
            "false_positive_indicators": [],
        })
        analyzer = FindingAnalyzer(_mock_llm(response))
        result = analyzer.analyze(_make_finding(), _make_context())
        assert result.is_real_vulnerability is True
        assert result.severity == SeverityLevel.CRITICAL
        assert result.exploitability == "easy"
        assert result.confidence >= 0.9

    def test_false_positive(self):
        response = json.dumps({
            "is_real_vulnerability": False,
            "confidence": 0.8,
            "severity": "informational",
            "exploitability": "theoretical",
            "reasoning": "WAF blocks the payload",
            "false_positive_indicators": ["WAF detected"],
        })
        analyzer = FindingAnalyzer(_mock_llm(response))
        result = analyzer.analyze(_make_finding(), _make_context())
        assert result.is_real_vulnerability is False
        assert result.severity == SeverityLevel.INFORMATIONAL

    def test_fallback_on_llm_error(self):
        mgr = MagicMock()
        mgr.complete.side_effect = Exception("LLM down")
        analyzer = FindingAnalyzer(mgr)
        result = analyzer.analyze(_make_finding(), _make_context())
        assert isinstance(result, FindingAnalysis)
        assert "Fallback" in result.reasoning

    def test_invalid_severity_defaults_to_informational(self):
        response = json.dumps({
            "is_real_vulnerability": True,
            "confidence": 0.7,
            "severity": "unknown_level",
            "exploitability": "moderate",
            "reasoning": "test",
            "false_positive_indicators": [],
        })
        analyzer = FindingAnalyzer(_mock_llm(response))
        result = analyzer.analyze(_make_finding(), _make_context())
        assert result.severity == SeverityLevel.INFORMATIONAL

    def test_invalid_exploitability_defaults_to_theoretical(self):
        response = json.dumps({
            "is_real_vulnerability": True,
            "confidence": 0.7,
            "severity": "high",
            "exploitability": "impossible",
            "reasoning": "test",
            "false_positive_indicators": [],
        })
        analyzer = FindingAnalyzer(_mock_llm(response))
        result = analyzer.analyze(_make_finding(), _make_context())
        assert result.exploitability == "theoretical"


class TestBatchAnalyze:
    def test_batch_returns_list(self):
        response = json.dumps({
            "is_real_vulnerability": True,
            "confidence": 0.9,
            "severity": "high",
            "exploitability": "moderate",
            "reasoning": "Real vuln",
            "false_positive_indicators": [],
        })
        analyzer = FindingAnalyzer(_mock_llm(response))
        findings = [_make_finding(), _make_finding()]
        results = analyzer.batch_analyze(findings, _make_context())
        assert len(results) == 2
        assert all(isinstance(r, FindingAnalysis) for r in results)


class TestFallbackClassify:
    def test_critical_keyword(self):
        finding = RawFinding(
            vulnerability_type="sql_injection",
            description="SQL injection found",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        analyzer = FindingAnalyzer(MagicMock())
        result = analyzer.fallback_classify(finding)
        assert result.severity == SeverityLevel.CRITICAL
        assert result.is_real_vulnerability is True

    def test_low_keyword(self):
        finding = RawFinding(
            vulnerability_type="open_redirect",
            description="Open redirect on /callback",
            evidence="test",
            affected_asset_id="a1",
            raw_data={},
        )
        analyzer = FindingAnalyzer(MagicMock())
        result = analyzer.fallback_classify(finding)
        assert result.severity == SeverityLevel.LOW
        assert result.is_real_vulnerability is False

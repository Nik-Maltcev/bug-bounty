"""Unit-тесты для IntentRouter."""

import json

import pytest
from unittest.mock import MagicMock

from app.models.ai_schemas import (
    IntentType,
    LLMResponse,
    ParsedIntent,
    ProviderType,
    SessionContext,
)
from app.services.ai.intent_router import IntentRouter


@pytest.fixture
def mock_llm_manager():
    return MagicMock()


@pytest.fixture
def router(mock_llm_manager):
    return IntentRouter(mock_llm_manager)


@pytest.fixture
def context():
    return SessionContext(
        program_id="prog-1",
        program_name="Test Program",
        rules=[],
        assets=[{"name": "example.com", "target": "https://example.com"}],
        recent_findings=[],
        recent_scans=[],
        conversation_history=[],
    )


def _make_llm_response(intent: str, confidence: float = 0.9, params: dict | None = None):
    """Helper to create a mock LLM response with JSON content."""
    data = {
        "intent": intent,
        "confidence": confidence,
        "params": params or {},
    }
    return LLMResponse(
        content=json.dumps(data),
        model="deepseek-v4-flash",
        usage={},
        provider=ProviderType.DEEPSEEK,
    )


# --- classify() with Russian messages ---


class TestClassifyRussian:
    def test_scan_intent_russian(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response(
            "scan", 0.95, {"target": "example.com", "scan_type": "xss"}
        )
        result = router.classify("Просканируй example.com на XSS", context)
        assert result.intent == IntentType.SCAN
        assert result.confidence >= 0.9
        assert result.params.get("target") == "example.com"

    def test_query_results_russian(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response("query_results", 0.9)
        result = router.classify("Какие уязвимости нашёл?", context)
        assert result.intent == IntentType.QUERY_RESULTS

    def test_clear_history_russian(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response("clear_history", 0.95)
        result = router.classify("Очисти историю чата", context)
        assert result.intent == IntentType.CLEAR_HISTORY


# --- classify() with English messages ---


class TestClassifyEnglish:
    def test_scan_intent_english(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response(
            "scan", 0.95, {"target": "example.com", "scan_type": "xss"}
        )
        result = router.classify("Scan example.com for XSS", context)
        assert result.intent == IntentType.SCAN

    def test_query_results_english(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response("query_results", 0.85)
        result = router.classify("What vulnerabilities did you find?", context)
        assert result.intent == IntentType.QUERY_RESULTS

    def test_analyze_finding_english(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response(
            "analyze_finding", 0.9, {"finding_id": "vuln-123"}
        )
        result = router.classify("Analyze the SQL injection on /login", context)
        assert result.intent == IntentType.ANALYZE_FINDING

    def test_generate_report_english(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response("generate_report", 0.9)
        result = router.classify("Generate report for SQL injection", context)
        assert result.intent == IntentType.GENERATE_REPORT

    def test_recommendations_english(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = _make_llm_response("recommendations", 0.85)
        result = router.classify("What should I check next?", context)
        assert result.intent == IntentType.RECOMMENDATIONS


# --- Fallback behavior ---


class TestFallback:
    def test_fallback_on_llm_error(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.side_effect = Exception("LLM unavailable")
        result = router.classify("Some message", context)
        assert result.intent == IntentType.GENERAL
        assert result.confidence == 0.0

    def test_fallback_on_invalid_json(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = LLMResponse(
            content="This is not JSON",
            model="deepseek-v4-flash",
            usage={},
            provider=ProviderType.DEEPSEEK,
        )
        result = router.classify("Some message", context)
        assert result.intent == IntentType.GENERAL
        assert result.confidence == 0.0

    def test_fallback_on_unknown_intent(self, router, mock_llm_manager, context):
        mock_llm_manager.complete.return_value = LLMResponse(
            content=json.dumps({"intent": "unknown_intent", "confidence": 0.5, "params": {}}),
            model="deepseek-v4-flash",
            usage={},
            provider=ProviderType.DEEPSEEK,
        )
        result = router.classify("Some message", context)
        # unknown_intent maps to GENERAL via ValueError in IntentType
        assert result.intent == IntentType.GENERAL


# --- _parse_response() ---


class TestParseResponse:
    def test_parses_valid_json(self, router):
        raw = json.dumps({"intent": "scan", "confidence": 0.9, "params": {"target": "example.com"}})
        result = router._parse_response(raw)
        assert result.intent == IntentType.SCAN
        assert result.confidence == 0.9
        assert result.params["target"] == "example.com"

    def test_parses_json_in_markdown_block(self, router):
        raw = '```json\n{"intent": "scan", "confidence": 0.8, "params": {}}\n```'
        result = router._parse_response(raw)
        assert result.intent == IntentType.SCAN

    def test_clamps_confidence(self, router):
        raw = json.dumps({"intent": "general", "confidence": 1.5, "params": {}})
        result = router._parse_response(raw)
        assert result.confidence == 1.0

    def test_clamps_negative_confidence(self, router):
        raw = json.dumps({"intent": "general", "confidence": -0.5, "params": {}})
        result = router._parse_response(raw)
        assert result.confidence == 0.0

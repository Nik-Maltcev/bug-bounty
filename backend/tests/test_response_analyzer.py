"""Тесты для ResponseAnalyzer — анализ HTTP-ответов."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from app.models.ai_scan_schemas import (
    AIRequest,
    AIRequestResult,
    AIRequestStatus,
    AnalysisResult,
    HypothesisStatus,
    TestHypothesis,
)
from app.services.ai.response_analyzer import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_REVIEW,
    ResponseAnalyzer,
)


@pytest.fixture
def mock_llm():
    """Mock LLM manager."""
    llm = MagicMock()
    return llm


@pytest.fixture
def analyzer(mock_llm) -> ResponseAnalyzer:
    """ResponseAnalyzer с mock LLM."""
    return ResponseAnalyzer(mock_llm)


def _hypothesis(
    hypothesis_id: str = "h1",
    vuln_type: str = "sqli",
    description: str = "SQL injection test",
) -> TestHypothesis:
    """Хелпер для создания гипотезы."""
    return TestHypothesis(
        id=hypothesis_id,
        scan_id="scan-1",
        description=description,
        rationale="Testing for SQL injection vulnerability",
        target_url="https://example.com/api",
        vulnerability_type=vuln_type,
        severity_estimate="high",
    )


def _request(
    request_id: str = "r1",
    hypothesis_id: str = "h1",
    expected_indicators: list[str] | None = None,
) -> AIRequest:
    """Хелпер для создания запроса."""
    return AIRequest(
        id=request_id,
        hypothesis_id=hypothesis_id,
        method="GET",
        url="https://example.com/api?id=1'",
        headers={"User-Agent": "TestAgent"},
        expected_indicators=expected_indicators or ["error", "syntax"],
    )


def _result(
    request_id: str = "r1",
    hypothesis_id: str = "h1",
    status_code: int = 200,
    body: str = "",
    error: str | None = None,
) -> AIRequestResult:
    """Хелпер для создания результата."""
    return AIRequestResult(
        request_id=request_id,
        hypothesis_id=hypothesis_id,
        status_code=status_code,
        response_headers={"Content-Type": "text/html"},
        response_body=body,
        duration_ms=100,
        error=error,
        executed_at=datetime.now(UTC),
    )


class TestAnalyzeWithError:
    """Тесты анализа при ошибке запроса."""

    def test_error_result_returns_not_confirmed(self, analyzer: ResponseAnalyzer):
        """Ошибка запроса возвращает is_confirmed=False."""
        hypothesis = _hypothesis()
        request = _request()
        result = _result(error="Connection timeout")

        analysis = analyzer.analyze(hypothesis, request, result)

        assert analysis.is_confirmed is False
        assert analysis.confidence == 0.0
        assert "timeout" in analysis.reasoning.lower()
        assert analysis.requires_manual_review is False


class TestAnalyzeWithLLM:
    """Тесты анализа через LLM."""

    def test_confirmed_high_confidence(self, analyzer: ResponseAnalyzer, mock_llm):
        """Подтверждённая уязвимость с высокой уверенностью."""
        mock_response = MagicMock()
        mock_response.content = '''```json
{
    "is_confirmed": true,
    "confidence": 0.95,
    "reasoning": "SQL error message found in response",
    "severity": "critical",
    "follow_up_hints": ["Try UNION injection"]
}
```'''
        mock_llm.complete.return_value = mock_response

        hypothesis = _hypothesis()
        request = _request()
        result = _result(body="SQL syntax error near '1'")

        analysis = analyzer.analyze(hypothesis, request, result)

        assert analysis.is_confirmed is True
        assert analysis.confidence == 0.95
        assert analysis.severity == "critical"
        assert analysis.requires_manual_review is False
        assert len(analysis.follow_up_hints) > 0

    def test_not_confirmed_low_confidence(self, analyzer: ResponseAnalyzer, mock_llm):
        """Не подтверждённая уязвимость с низкой уверенностью."""
        mock_response = MagicMock()
        mock_response.content = '''{
    "is_confirmed": false,
    "confidence": 0.2,
    "reasoning": "No indicators found",
    "severity": "informational",
    "follow_up_hints": []
}'''
        mock_llm.complete.return_value = mock_response

        hypothesis = _hypothesis()
        request = _request()
        result = _result(body="Normal response")

        analysis = analyzer.analyze(hypothesis, request, result)

        assert analysis.is_confirmed is False
        assert analysis.confidence == 0.2
        assert analysis.requires_manual_review is False

    def test_requires_manual_review_medium_confidence(self, analyzer: ResponseAnalyzer, mock_llm):
        """Средняя уверенность требует ручной проверки."""
        mock_response = MagicMock()
        mock_response.content = '''{
    "is_confirmed": true,
    "confidence": 0.55,
    "reasoning": "Possible SQL error, but unclear",
    "severity": "medium",
    "follow_up_hints": []
}'''
        mock_llm.complete.return_value = mock_response

        hypothesis = _hypothesis()
        request = _request()
        result = _result(body="Some ambiguous response")

        analysis = analyzer.analyze(hypothesis, request, result)

        # confidence 0.55 — между CONFIDENCE_REVIEW (0.4) и CONFIDENCE_CONFIRMED (0.7)
        assert analysis.requires_manual_review is True
        # is_confirmed зависит от реализации — LLM сказал true, confidence < 0.7
        # Текущая реализация: если LLM сказал true и confidence >= 0.4, оставляет true
        assert CONFIDENCE_REVIEW <= analysis.confidence < CONFIDENCE_CONFIRMED

    def test_llm_error_returns_manual_review(self, analyzer: ResponseAnalyzer, mock_llm):
        """Ошибка LLM возвращает результат для ручной проверки."""
        mock_llm.complete.side_effect = Exception("LLM API error")

        hypothesis = _hypothesis()
        request = _request()
        result = _result(body="Some response")

        analysis = analyzer.analyze(hypothesis, request, result)

        assert analysis.is_confirmed is False
        assert analysis.requires_manual_review is True
        assert "ошибка" in analysis.reasoning.lower() or "error" in analysis.reasoning.lower()


class TestConfidenceThresholds:
    """Тесты порогов уверенности."""

    def test_confidence_above_confirmed_threshold(self, analyzer: ResponseAnalyzer, mock_llm):
        """Уверенность >= 0.7 подтверждает уязвимость."""
        mock_response = MagicMock()
        mock_response.content = f'''{{"is_confirmed": false, "confidence": {CONFIDENCE_CONFIRMED}, "reasoning": "test", "severity": "high", "follow_up_hints": []}}'''
        mock_llm.complete.return_value = mock_response

        analysis = analyzer.analyze(_hypothesis(), _request(), _result())

        # Даже если LLM сказал is_confirmed=false, высокая уверенность переопределяет
        assert analysis.is_confirmed is True
        assert analysis.requires_manual_review is False

    def test_confidence_below_review_threshold(self, analyzer: ResponseAnalyzer, mock_llm):
        """Уверенность < 0.4 не подтверждает уязвимость."""
        mock_response = MagicMock()
        mock_response.content = f'''{{"is_confirmed": true, "confidence": {CONFIDENCE_REVIEW - 0.1}, "reasoning": "test", "severity": "low", "follow_up_hints": []}}'''
        mock_llm.complete.return_value = mock_response

        analysis = analyzer.analyze(_hypothesis(), _request(), _result())

        # Даже если LLM сказал is_confirmed=true, низкая уверенность переопределяет
        assert analysis.is_confirmed is False
        assert analysis.requires_manual_review is False

    def test_confidence_in_review_range(self, analyzer: ResponseAnalyzer, mock_llm):
        """Уверенность 0.4-0.7 требует ручной проверки."""
        mock_response = MagicMock()
        mock_response.content = '''{
            "is_confirmed": true,
            "confidence": 0.5,
            "reasoning": "Unclear indicators",
            "severity": "medium",
            "follow_up_hints": []
        }'''
        mock_llm.complete.return_value = mock_response

        analysis = analyzer.analyze(_hypothesis(), _request(), _result())

        assert analysis.requires_manual_review is True
        assert CONFIDENCE_REVIEW <= analysis.confidence < CONFIDENCE_CONFIRMED


class TestQuickCheck:
    """Тесты quick_check без LLM."""

    def test_quick_check_finds_indicator(self, analyzer: ResponseAnalyzer):
        """quick_check находит индикатор в ответе."""
        hypothesis = _hypothesis()
        request = _request(expected_indicators=["root:", "etc/passwd"])
        result = _result(body="root:x:0:0:root:/root:/bin/bash")

        assert analyzer.quick_check(hypothesis, request, result) is True

    def test_quick_check_no_indicator(self, analyzer: ResponseAnalyzer):
        """quick_check не находит индикатор."""
        hypothesis = _hypothesis()
        request = _request(expected_indicators=["root:", "etc/passwd"])
        result = _result(body="Normal page content")

        assert analyzer.quick_check(hypothesis, request, result) is False

    def test_quick_check_empty_indicators(self, analyzer: ResponseAnalyzer):
        """quick_check с пустыми индикаторами возвращает False."""
        hypothesis = _hypothesis()
        request = _request(expected_indicators=[])
        result = _result(body="Some content")

        assert analyzer.quick_check(hypothesis, request, result) is False

    def test_quick_check_empty_body(self, analyzer: ResponseAnalyzer):
        """quick_check с пустым телом возвращает False."""
        hypothesis = _hypothesis()
        request = _request(expected_indicators=["error"])
        result = _result(body="")

        assert analyzer.quick_check(hypothesis, request, result) is False

    def test_quick_check_case_insensitive(self, analyzer: ResponseAnalyzer):
        """quick_check регистронезависимый."""
        hypothesis = _hypothesis()
        request = _request(expected_indicators=["ERROR"])
        result = _result(body="sql error occurred")

        assert analyzer.quick_check(hypothesis, request, result) is True


class TestClassifySeverity:
    """Тесты classify_severity."""

    def test_rce_is_critical(self, analyzer: ResponseAnalyzer):
        """RCE классифицируется как critical."""
        severity = analyzer.classify_severity("rce", 0.9, [])
        assert severity == "critical"

    def test_sqli_is_critical(self, analyzer: ResponseAnalyzer):
        """SQLi классифицируется как critical."""
        severity = analyzer.classify_severity("sqli", 0.9, [])
        assert severity == "critical"

    def test_ssrf_is_high(self, analyzer: ResponseAnalyzer):
        """SSRF классифицируется как high."""
        severity = analyzer.classify_severity("ssrf", 0.9, [])
        assert severity == "high"

    def test_xss_is_medium(self, analyzer: ResponseAnalyzer):
        """XSS классифицируется как medium."""
        severity = analyzer.classify_severity("xss", 0.9, [])
        assert severity == "medium"

    def test_open_redirect_is_low(self, analyzer: ResponseAnalyzer):
        """Open redirect классифицируется как low."""
        severity = analyzer.classify_severity("open_redirect", 0.9, [])
        assert severity == "low"

    def test_low_confidence_downgrades_severity(self, analyzer: ResponseAnalyzer):
        """Низкая уверенность понижает серьёзность."""
        # critical -> high при низкой уверенности
        severity = analyzer.classify_severity("rce", 0.3, [])
        assert severity == "high"

    def test_unknown_type_defaults_to_medium(self, analyzer: ResponseAnalyzer):
        """Неизвестный тип по умолчанию medium."""
        severity = analyzer.classify_severity("unknown_vuln_type", 0.9, [])
        assert severity == "medium"


class TestParseAnalysisResponse:
    """Тесты парсинга ответа LLM."""

    def test_parse_json_with_markdown(self, analyzer: ResponseAnalyzer):
        """Парсит JSON в markdown code block."""
        content = '''```json
{
    "is_confirmed": true,
    "confidence": 0.85,
    "reasoning": "Found vulnerability",
    "severity": "high",
    "follow_up_hints": ["hint1", "hint2"]
}
```'''
        result = analyzer._parse_analysis_response(content, "h1", "r1")

        assert result.is_confirmed is True
        assert result.confidence == 0.85
        assert result.severity == "high"
        assert len(result.follow_up_hints) == 2

    def test_parse_plain_json(self, analyzer: ResponseAnalyzer):
        """Парсит plain JSON."""
        content = '{"is_confirmed": false, "confidence": 0.3, "reasoning": "No vuln", "severity": "informational", "follow_up_hints": []}'
        result = analyzer._parse_analysis_response(content, "h1", "r1")

        assert result.is_confirmed is False
        assert result.confidence == 0.3

    def test_parse_invalid_json_raises(self, analyzer: ResponseAnalyzer):
        """Невалидный JSON вызывает исключение."""
        content = "not valid json"

        with pytest.raises(Exception):
            analyzer._parse_analysis_response(content, "h1", "r1")

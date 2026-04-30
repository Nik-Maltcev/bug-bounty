"""Tests for RuleAnalyzer — semantic rule analysis with mocked LLM."""

import json
import pytest
from unittest.mock import MagicMock

from app.models.ai_schemas import LLMResponse, ProviderType, RuleAnalysisResult
from app.models.schemas import ProgramRule
from app.services.ai.rule_analyzer import RuleAnalyzer
from app.services.compliance_manager import ComplianceManager


def _make_rules():
    return [
        ProgramRule(id="R1", description="SQL injection testing is allowed", is_allowed=True, category="testing_method"),
        ProgramRule(id="R2", description="Do not use automated tools like sqlmap", is_allowed=False, category="testing_method"),
        ProgramRule(id="R3", description="Do not test production databases", is_allowed=False, category="scope"),
    ]


def _mock_llm(content: str):
    mgr = MagicMock()
    mgr.complete.return_value = LLMResponse(
        content=content, model="test", usage={}, provider=ProviderType.DEEPSEEK
    )
    return mgr


class TestAnalyzeAction:
    def test_allowed_action_high_confidence(self):
        response = json.dumps({
            "is_allowed": True, "confidence": 0.9,
            "reasoning": "Manual SQL injection testing is allowed",
            "relevant_rules": ["R1"],
        })
        analyzer = RuleAnalyzer(_mock_llm(response))
        result = analyzer.analyze_action("Manual SQL injection test on /login", _make_rules())
        assert result.is_allowed is True
        assert result.confidence >= 0.7
        assert "R1" in result.relevant_rules

    def test_blocked_action(self):
        response = json.dumps({
            "is_allowed": False, "confidence": 0.95,
            "reasoning": "Automated tools are forbidden",
            "relevant_rules": ["R2"],
        })
        analyzer = RuleAnalyzer(_mock_llm(response))
        result = analyzer.analyze_action("Run sqlmap against /api", _make_rules())
        assert result.is_allowed is False
        assert "R2" in result.relevant_rules

    def test_conservative_low_confidence(self):
        """confidence < 0.7 → is_allowed must be False."""
        response = json.dumps({
            "is_allowed": True, "confidence": 0.5,
            "reasoning": "Unclear if allowed",
            "relevant_rules": ["R1"],
        })
        analyzer = RuleAnalyzer(_mock_llm(response))
        result = analyzer.analyze_action("Some ambiguous action", _make_rules())
        assert result.is_allowed is False
        assert result.confidence < 0.7
        assert "Conservative" in result.reasoning

    def test_fallback_on_llm_error(self):
        mgr = MagicMock()
        mgr.complete.side_effect = Exception("LLM down")
        analyzer = RuleAnalyzer(mgr)
        result = analyzer.analyze_action("Run sqlmap", _make_rules())
        assert isinstance(result, RuleAnalysisResult)
        assert "Fallback" in result.reasoning

    def test_invalid_rule_ids_filtered(self):
        response = json.dumps({
            "is_allowed": True, "confidence": 0.9,
            "reasoning": "OK",
            "relevant_rules": ["R1", "INVALID_ID"],
        })
        analyzer = RuleAnalyzer(_mock_llm(response))
        result = analyzer.analyze_action("test", _make_rules())
        assert "INVALID_ID" not in result.relevant_rules


class TestAnswerRuleQuestion:
    def test_returns_answer(self):
        mgr = _mock_llm("Based on rule R2, sqlmap is not allowed.")
        analyzer = RuleAnalyzer(mgr)
        answer = analyzer.answer_rule_question("Can I use sqlmap?", _make_rules())
        assert "R2" in answer or "sqlmap" in answer

    def test_fallback_on_error(self):
        mgr = MagicMock()
        mgr.complete.side_effect = Exception("LLM down")
        analyzer = RuleAnalyzer(mgr)
        answer = analyzer.answer_rule_question("Can I use sqlmap?", _make_rules())
        assert "Unable" in answer or "R1" in answer


class TestFallbackCheck:
    def test_fallback_uses_compliance_manager(self):
        mgr = MagicMock()
        analyzer = RuleAnalyzer(mgr)
        result = analyzer.fallback_check("Run sqlmap against target", _make_rules())
        assert isinstance(result, RuleAnalysisResult)
        assert "Fallback" in result.reasoning

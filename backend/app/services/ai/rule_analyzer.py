"""RuleAnalyzer — семантический анализ правил программы через LLM.

Анализирует допустимость действий, отвечает на вопросы о правилах,
с fallback на keyword-based логику ComplianceManager.
"""

import json
import logging

from app.models.ai_schemas import RuleAnalysisResult
from app.models.schemas import ProgramRule
from app.services.ai.llm_provider_manager import LLMProviderManager
from app.services.compliance_manager import AgentAction, ComplianceManager

logger = logging.getLogger(__name__)

RULE_ANALYSIS_SYSTEM_PROMPT = """Ты — анализатор правил программы тестирования безопасности.
По набору правил программы и описанию действия определи, разрешено ли действие.

Формат правил: каждое правило содержит id, описание, is_allowed (true=разрешено, false=запрещено) и категорию.

Отвечай ТОЛЬКО валидным JSON:
{"is_allowed": true/false, "confidence": 0.0-1.0, "reasoning": "объяснение", "relevant_rules": ["rule_id1", "rule_id2"]}

Будь консервативен: если не уверен — отмечай как запрещённое. Отвечай на русском языке."""

RULE_QUESTION_SYSTEM_PROMPT = """Ты — эксперт по правилам программ тестирования безопасности.
Отвечай на вопросы пользователя о правилах программы. Всегда цитируй конкретные ID правил.
Будь точен и ссылайся на фактический текст правил. Отвечай на русском языке."""


class RuleAnalyzer:
    """Семантический анализатор правил программы."""

    CONFIDENCE_THRESHOLD = 0.7

    def __init__(
        self,
        llm_manager: LLMProviderManager,
        compliance_manager: ComplianceManager | None = None,
    ):
        self._llm = llm_manager
        self._compliance = compliance_manager or ComplianceManager()

    def analyze_action(
        self,
        action_description: str,
        rules: list[ProgramRule],
    ) -> RuleAnalysisResult:
        """Анализирует допустимость действия через LLM.

        При confidence < 0.7 — консервативная интерпретация (запрет).
        """
        try:
            rules_text = self._format_rules(rules)
            messages = [
                {"role": "system", "content": RULE_ANALYSIS_SYSTEM_PROMPT},
                {"role": "user", "content": f"Rules:\n{rules_text}\n\nAction: {action_description}"},
            ]
            response = self._llm.complete(messages)
            result = self._parse_analysis(response.content, rules)

            # Conservative interpretation: low confidence → not allowed
            if result.confidence < self.CONFIDENCE_THRESHOLD:
                result = RuleAnalysisResult(
                    is_allowed=False,
                    confidence=result.confidence,
                    reasoning=result.reasoning + " [Conservative: low confidence → denied]",
                    relevant_rules=result.relevant_rules,
                )
            return result
        except Exception as e:
            logger.warning(f"LLM rule analysis failed, using fallback: {e}")
            return self.fallback_check(action_description, rules)

    def answer_rule_question(
        self,
        question: str,
        rules: list[ProgramRule],
    ) -> str:
        """Отвечает на вопрос о правилах с цитированием."""
        try:
            rules_text = self._format_rules(rules)
            messages = [
                {"role": "system", "content": RULE_QUESTION_SYSTEM_PROMPT},
                {"role": "user", "content": f"Rules:\n{rules_text}\n\nQuestion: {question}"},
            ]
            response = self._llm.complete(messages)
            return response.content
        except Exception as e:
            logger.warning(f"LLM rule question failed: {e}")
            rule_ids = [r.id for r in rules]
            return f"Не удалось проанализировать правила через LLM. Доступные правила: {', '.join(rule_ids)}. Проверьте их вручную."

    def fallback_check(
        self,
        action_description: str,
        rules: list[ProgramRule],
    ) -> RuleAnalysisResult:
        """Fallback на keyword-based логику ComplianceManager."""
        action = AgentAction(
            action_type="check",
            target="unknown",
            description=action_description,
        )
        result = self._compliance.validate_action(action, rules)
        relevant = [result.rule_reference] if result.rule_reference else []
        return RuleAnalysisResult(
            is_allowed=result.action_allowed,
            confidence=0.5,
            reasoning=result.reason + " [Fallback: keyword-based]",
            relevant_rules=relevant,
        )

    @staticmethod
    def _format_rules(rules: list[ProgramRule]) -> str:
        lines = []
        for r in rules:
            status = "ALLOWED" if r.is_allowed else "FORBIDDEN"
            lines.append(f"[{r.id}] ({status}) {r.description} (category: {r.category})")
        return "\n".join(lines)

    @staticmethod
    def _parse_analysis(raw: str, rules: list[ProgramRule]) -> RuleAnalysisResult:
        """Parse LLM JSON response into RuleAnalysisResult."""
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            json_lines = []
            in_block = False
            for line in lines:
                if line.startswith("```") and not in_block:
                    in_block = True
                    continue
                elif line.startswith("```") and in_block:
                    break
                elif in_block:
                    json_lines.append(line)
            cleaned = "\n".join(json_lines)

        data = json.loads(cleaned)
        valid_ids = {r.id for r in rules}
        relevant = [rid for rid in data.get("relevant_rules", []) if rid in valid_ids]

        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        return RuleAnalysisResult(
            is_allowed=bool(data.get("is_allowed", False)),
            confidence=confidence,
            reasoning=str(data.get("reasoning", "")),
            relevant_rules=relevant,
        )

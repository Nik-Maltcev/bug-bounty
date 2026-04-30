"""IntentRouter — маршрутизатор намерений пользователя через LLM.

Классифицирует намерение пользователя и извлекает параметры действия.
Поддерживает русский и английский языки.
"""

import json
import logging

from app.core.ai_exceptions import IntentClassificationError
from app.models.ai_schemas import IntentType, LLMResponse, ParsedIntent, SessionContext
from app.services.ai.llm_provider_manager import LLMProviderManager

logger = logging.getLogger(__name__)

INTENT_SYSTEM_PROMPT = """Ты — классификатор намерений для Сканера сайтов.
Классифицируй сообщение пользователя ровно в ОДНУ из категорий:
- scan: пользователь хочет запустить сканирование (например, «Просканируй example.com», «Scan example.com for XSS»)
- query_results: пользователь спрашивает о результатах сканирования (например, «Какие уязвимости нашёл?», «What vulnerabilities did you find?»)
- analyze_finding: пользователь хочет подробный анализ находки (например, «Проанализируй SQL-инъекцию на /login»)
- generate_report: пользователь хочет сгенерировать отчёт (например, «Сгенерируй отчёт», «Generate report»)
- query_rules: пользователь спрашивает о правилах программы (например, «Можно ли использовать sqlmap?»)
- recommendations: пользователь просит рекомендации (например, «Что проверить дальше?»)
- clear_history: пользователь хочет очистить историю чата (например, «Очисти историю»)
- general: любое другое сообщение

Отвечай ТОЛЬКО валидным JSON в формате:
{"intent": "<intent_type>", "confidence": <0.0-1.0>, "params": {"target": "...", "scan_type": "...", "finding_id": "..."}}

Включай только релевантные params. Для general — params должны быть {}.
Поддерживай русский и английский языки."""


class IntentRouter:
    """Маршрутизатор намерений пользователя через LLM."""

    def __init__(self, llm_manager: LLMProviderManager):
        self._llm = llm_manager

    def classify(
        self,
        message: str,
        context: SessionContext,
    ) -> ParsedIntent:
        """Классифицирует намерение и извлекает параметры.

        Поддерживает русский и английский языки.
        Fallback на intent=GENERAL при ошибке.
        """
        try:
            messages = self._build_classification_prompt(message, context)
            response: LLMResponse = self._llm.complete(messages)
            return self._parse_response(response.content)
        except (IntentClassificationError, Exception) as e:
            logger.warning(f"Intent classification failed, falling back to GENERAL: {e}")
            return ParsedIntent(
                intent=IntentType.GENERAL,
                params={},
                confidence=0.0,
            )

    def _build_classification_prompt(
        self,
        message: str,
        context: SessionContext,
    ) -> list[dict[str, str]]:
        """Формирует промпт для классификации намерения."""
        context_summary = f"Program: {context.program_name} (ID: {context.program_id})"
        if context.assets:
            asset_names = [a.get("name", "") for a in context.assets[:5]]
            context_summary += f"\nAssets: {', '.join(asset_names)}"

        return [
            {"role": "system", "content": INTENT_SYSTEM_PROMPT},
            {"role": "user", "content": f"Context: {context_summary}\n\nUser message: {message}"},
        ]

    def _parse_response(self, raw_response: str) -> ParsedIntent:
        """Парсит JSON-ответ LLM в ParsedIntent."""
        try:
            # Извлекаем JSON из ответа (LLM может обернуть в markdown)
            cleaned = raw_response.strip()
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

            intent_str = data.get("intent", "general")
            try:
                intent = IntentType(intent_str)
            except ValueError:
                intent = IntentType.GENERAL

            confidence = float(data.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            params = data.get("params", {})
            if not isinstance(params, dict):
                params = {}

            return ParsedIntent(
                intent=intent,
                params=params,
                confidence=confidence,
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise IntentClassificationError(
                message="Failed to parse LLM response",
                raw_response=raw_response,
            ) from e

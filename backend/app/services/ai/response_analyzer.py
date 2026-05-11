"""ResponseAnalyzer — анализ HTTP-ответов через LLM.

Анализирует ответы на AI-запросы и определяет,
подтверждается ли гипотеза об уязвимости.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime

from app.models.ai_scan_schemas import (
    AIRequest,
    AIRequestResult,
    AnalysisResult,
    TestHypothesis,
)
from app.services.ai.llm_provider_manager import LLMProviderManager

logger = logging.getLogger(__name__)


# Пороги уверенности
CONFIDENCE_CONFIRMED = 0.7  # >= 0.7 = подтверждено
CONFIDENCE_REVIEW = 0.4     # 0.4-0.7 = требует ручной проверки
# < 0.4 = не подтверждено


class ResponseAnalyzer:
    """Анализирует HTTP-ответы и определяет наличие уязвимостей."""

    def __init__(self, llm_manager: LLMProviderManager) -> None:
        """Инициализация анализатора.

        Args:
            llm_manager: менеджер LLM для анализа.
        """
        self._llm = llm_manager

    def analyze(
        self,
        hypothesis: TestHypothesis,
        request: AIRequest,
        result: AIRequestResult,
    ) -> AnalysisResult:
        """Анализирует ответ и определяет, подтверждена ли уязвимость.

        Args:
            hypothesis: исходная гипотеза.
            request: выполненный запрос.
            result: результат выполнения.

        Returns:
            Результат анализа с confidence и reasoning.
        """
        # Если запрос завершился ошибкой
        if result.error:
            return AnalysisResult(
                hypothesis_id=hypothesis.id,
                request_id=request.id,
                is_confirmed=False,
                confidence=0.0,
                reasoning=f"Запрос завершился ошибкой: {result.error}",
                severity="informational",
                requires_manual_review=False,
                follow_up_hints=[],
                analyzed_at=datetime.now(UTC),
            )

        # Формируем промпт для анализа
        prompt = self._build_analysis_prompt(hypothesis, request, result)

        try:
            messages = [
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": prompt},
            ]
            response = self._llm.complete(messages)
            analysis = self._parse_analysis_response(response.content, hypothesis.id, request.id)

            logger.info(
                "Analysis for hypothesis %s: confirmed=%s, confidence=%.2f",
                hypothesis.id,
                analysis.is_confirmed,
                analysis.confidence,
            )
            return analysis

        except Exception as e:
            logger.error("Failed to analyze response for hypothesis %s: %s", hypothesis.id, e)
            # Возвращаем результат с низкой уверенностью для ручной проверки
            return AnalysisResult(
                hypothesis_id=hypothesis.id,
                request_id=request.id,
                is_confirmed=False,
                confidence=0.3,
                reasoning=f"Ошибка анализа LLM: {e}. Требуется ручная проверка.",
                severity="informational",
                requires_manual_review=True,
                follow_up_hints=[],
                analyzed_at=datetime.now(UTC),
            )

    def _get_system_prompt(self) -> str:
        """Возвращает системный промпт для анализа."""
        return """Ты — эксперт по безопасности веб-приложений. Твоя задача — анализировать HTTP-ответы и определять, подтверждается ли гипотеза об уязвимости.

Правила анализа:
1. Будь консервативен — лучше пропустить уязвимость, чем дать ложное срабатывание
2. Ищи конкретные индикаторы уязвимости в ответе
3. Учитывай контекст: статус-код, заголовки, тело ответа
4. Оценивай confidence от 0.0 до 1.0:
   - 0.9-1.0: явное подтверждение (например, содержимое /etc/passwd в ответе)
   - 0.7-0.9: сильные индикаторы (ошибки SQL, stack traces)
   - 0.4-0.7: косвенные признаки (требует ручной проверки)
   - 0.0-0.4: нет подтверждения

Отвечай только валидным JSON."""

    def _build_analysis_prompt(
        self,
        hypothesis: TestHypothesis,
        request: AIRequest,
        result: AIRequestResult,
    ) -> str:
        """Формирует промпт для анализа."""
        # Обрезаем тело ответа для промпта
        body_preview = result.response_body[:4000] if result.response_body else "empty"

        # Форматируем заголовки
        headers_str = "\n".join(f"  {k}: {v}" for k, v in result.response_headers.items())

        return f"""## Гипотеза
Тип уязвимости: {hypothesis.vulnerability_type}
Описание: {hypothesis.description}
Обоснование: {hypothesis.rationale}

## Запрос
{request.method} {request.url}
Headers: {json.dumps(request.headers, ensure_ascii=False)}
Body: {request.body or 'null'}

## Ожидаемые индикаторы
{', '.join(request.expected_indicators) if request.expected_indicators else 'не указаны'}

## Ответ
Status: {result.status_code}
Headers:
{headers_str}

Body (preview):
{body_preview}

## Задача
Проанализируй ответ и определи:
1. Подтверждается ли гипотеза об уязвимости?
2. Какова уверенность (0.0-1.0)?
3. Обоснуй вывод
4. Определи серьёзность (critical, high, medium, low, informational)
5. Предложи follow-up тесты если есть интересные находки

## Формат ответа (JSON)
```json
{{
  "is_confirmed": true,
  "confidence": 0.85,
  "reasoning": "Обнаружено содержимое /etc/passwd в ответе: root:x:0:0...",
  "severity": "high",
  "follow_up_hints": ["Проверить другие файлы через path traversal", "Попробовать null byte injection"]
}}
```

Только JSON, без пояснений."""

    def _parse_analysis_response(
        self, content: str, hypothesis_id: str, request_id: str
    ) -> AnalysisResult:
        """Парсит JSON-ответ LLM в AnalysisResult."""
        # Убираем markdown code blocks
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"```(?:json)?\n?", "", content)
            content = content.strip()

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse analysis JSON: %s", e)
            raise

        confidence = float(data.get("confidence", 0.0))
        is_confirmed = data.get("is_confirmed", False)

        # Определяем requires_manual_review по порогам
        requires_manual_review = CONFIDENCE_REVIEW <= confidence < CONFIDENCE_CONFIRMED

        # Корректируем is_confirmed по порогам
        if confidence >= CONFIDENCE_CONFIRMED:
            is_confirmed = True
        elif confidence < CONFIDENCE_REVIEW:
            is_confirmed = False

        return AnalysisResult(
            hypothesis_id=hypothesis_id,
            request_id=request_id,
            is_confirmed=is_confirmed,
            confidence=confidence,
            reasoning=data.get("reasoning", ""),
            severity=data.get("severity", "informational"),
            requires_manual_review=requires_manual_review,
            follow_up_hints=data.get("follow_up_hints", []),
            analyzed_at=datetime.now(UTC),
        )

    def quick_check(
        self,
        hypothesis: TestHypothesis,
        request: AIRequest,
        result: AIRequestResult,
    ) -> bool:
        """Быстрая проверка без LLM — ищет expected_indicators в ответе.

        Args:
            hypothesis: гипотеза.
            request: запрос.
            result: результат.

        Returns:
            True если найден хотя бы один индикатор.
        """
        if not request.expected_indicators:
            return False

        if not result.response_body:
            return False

        body_lower = result.response_body.lower()
        for indicator in request.expected_indicators:
            if indicator.lower() in body_lower:
                logger.debug(
                    "Quick check: found indicator '%s' in response for hypothesis %s",
                    indicator,
                    hypothesis.id,
                )
                return True

        return False

    def classify_severity(
        self,
        vulnerability_type: str,
        confidence: float,
        response_indicators: list[str],
    ) -> str:
        """Классифицирует серьёзность уязвимости.

        Args:
            vulnerability_type: тип уязвимости.
            confidence: уверенность.
            response_indicators: найденные индикаторы.

        Returns:
            Уровень серьёзности.
        """
        # Базовая серьёзность по типу
        severity_map = {
            "rce": "critical",
            "remote_code_execution": "critical",
            "sqli": "critical",
            "sql_injection": "critical",
            "ssrf": "high",
            "server_side_request_forgery": "high",
            "lfi": "high",
            "local_file_inclusion": "high",
            "path_traversal": "high",
            "xxe": "high",
            "xml_external_entity": "high",
            "ssti": "high",
            "server_side_template_injection": "high",
            "idor": "medium",
            "insecure_direct_object_reference": "medium",
            "xss": "medium",
            "cross_site_scripting": "medium",
            "csrf": "medium",
            "cross_site_request_forgery": "medium",
            "open_redirect": "low",
            "information_disclosure": "low",
        }

        base_severity = severity_map.get(vulnerability_type.lower(), "medium")

        # Понижаем серьёзность при низкой уверенности
        if confidence < 0.5:
            severity_order = ["critical", "high", "medium", "low", "informational"]
            current_idx = severity_order.index(base_severity) if base_severity in severity_order else 2
            return severity_order[min(current_idx + 1, len(severity_order) - 1)]

        return base_severity

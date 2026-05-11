"""HypothesisEngine — генерация гипотез и HTTP-запросов через LLM.

Анализирует технологии и находки Stage 1, генерирует гипотезы
об уязвимостях и формирует конкретные HTTP-запросы для их проверки.
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
    AIRequestStatus,
    HypothesisStatus,
    TechnologyFingerprint,
    TestHypothesis,
)
from app.models.schemas import RawFinding
from app.services.ai.llm_provider_manager import LLMProviderManager

logger = logging.getLogger(__name__)


# Приоритет типов уязвимостей по серьёзности
VULNERABILITY_PRIORITY = {
    "rce": 1,
    "remote_code_execution": 1,
    "sqli": 2,
    "sql_injection": 2,
    "ssrf": 3,
    "server_side_request_forgery": 3,
    "lfi": 4,
    "local_file_inclusion": 4,
    "path_traversal": 4,
    "xxe": 5,
    "xml_external_entity": 5,
    "ssti": 6,
    "server_side_template_injection": 6,
    "idor": 7,
    "insecure_direct_object_reference": 7,
    "xss": 8,
    "cross_site_scripting": 8,
    "csrf": 9,
    "cross_site_request_forgery": 9,
    "open_redirect": 10,
    "information_disclosure": 11,
}


class HypothesisEngine:
    """Генерирует гипотезы об уязвимостях и HTTP-запросы для их проверки."""

    def __init__(self, llm_manager: LLMProviderManager) -> None:
        """Инициализация engine.

        Args:
            llm_manager: менеджер LLM для генерации.
        """
        self._llm = llm_manager

    def generate(
        self,
        scan_id: str,
        fingerprints: list[TechnologyFingerprint],
        findings: list[RawFinding],
        target_url: str,
        iteration: int = 0,
        previous_results: list[AIRequestResult] | None = None,
    ) -> list[TestHypothesis]:
        """Генерирует гипотезы на основе технологий и находок.

        Args:
            scan_id: ID сканирования.
            fingerprints: идентифицированные технологии.
            findings: находки Stage 1.
            target_url: базовый URL цели.
            iteration: номер итерации (0 = начальная).
            previous_results: результаты предыдущих тестов (для follow-up).

        Returns:
            Список гипотез, отсортированных по приоритету.
        """
        if iteration == 0:
            return self._generate_initial(scan_id, fingerprints, findings, target_url)
        else:
            return self._generate_followup(
                scan_id, fingerprints, findings, target_url, iteration, previous_results or []
            )

    def _generate_initial(
        self,
        scan_id: str,
        fingerprints: list[TechnologyFingerprint],
        findings: list[RawFinding],
        target_url: str,
    ) -> list[TestHypothesis]:
        """Генерирует начальные гипотезы."""
        # Формируем контекст для LLM
        tech_context = self._format_technologies(fingerprints)
        findings_context = self._format_findings(findings)

        prompt = f"""Ты — эксперт по безопасности веб-приложений. Проанализируй данные и сгенерируй гипотезы об уязвимостях.

## Цель
{target_url}

## Обнаруженные технологии
{tech_context}

## Находки Stage 1
{findings_context}

## Задача
Сгенерируй список гипотез об уязвимостях для проверки. Для каждой гипотезы укажи:
1. Тип уязвимости (path_traversal, sqli, ssrf, xss, lfi, rce, idor, xxe, ssti, open_redirect, information_disclosure)
2. Описание гипотезы
3. Обоснование ("Я тестирую это, потому что...")
4. Целевой URL/эндпоинт
5. Оценку серьёзности (critical, high, medium, low)

## Формат ответа (JSON)
```json
[
  {{
    "vulnerability_type": "path_traversal",
    "description": "Path traversal через параметр file",
    "rationale": "Я тестирую это, потому что nginx 1.18 имеет известную уязвимость CVE-2021-23017",
    "target_url": "{target_url}/download?file=../../../etc/passwd",
    "severity_estimate": "high",
    "source_fingerprint_id": "id_технологии_или_null",
    "source_finding_id": "id_находки_или_null"
  }}
]
```

Сгенерируй 5-10 наиболее вероятных гипотез. Приоритизируй critical и high уязвимости.
Только JSON, без пояснений."""

        try:
            messages = [
                {"role": "system", "content": "Ты — эксперт по пентесту. Отвечай только валидным JSON."},
                {"role": "user", "content": prompt},
            ]
            response = self._llm.complete(messages)
            hypotheses = self._parse_hypotheses_response(response.content, scan_id)

            # Сортируем по приоритету
            hypotheses.sort(key=lambda h: VULNERABILITY_PRIORITY.get(h.vulnerability_type.lower(), 100))

            logger.info("Generated %d initial hypotheses", len(hypotheses))
            return hypotheses

        except Exception as e:
            logger.error("Failed to generate hypotheses: %s", e)
            return []

    def _generate_followup(
        self,
        scan_id: str,
        fingerprints: list[TechnologyFingerprint],
        findings: list[RawFinding],
        target_url: str,
        iteration: int,
        previous_results: list[AIRequestResult],
    ) -> list[TestHypothesis]:
        """Генерирует follow-up гипотезы на основе предыдущих результатов."""
        # Формируем контекст предыдущих результатов
        results_context = self._format_previous_results(previous_results)

        prompt = f"""Ты — эксперт по безопасности. Проанализируй результаты предыдущих тестов и сгенерируй follow-up гипотезы.

## Цель
{target_url}

## Итерация
{iteration} из 3

## Результаты предыдущих тестов
{results_context}

## Задача
На основе полученных ответов сгенерируй follow-up гипотезы для углублённого тестирования:
- Если обнаружены новые эндпоинты — протестируй их
- Если ответ содержит интересные данные — исследуй глубже
- Если частичный успех — попробуй вариации payload

## Формат ответа (JSON)
```json
[
  {{
    "vulnerability_type": "sqli",
    "description": "SQL injection в обнаруженном параметре id",
    "rationale": "Предыдущий тест показал ошибку SQL в ответе",
    "target_url": "{target_url}/api/user?id=1' AND '1'='1",
    "severity_estimate": "high",
    "parent_hypothesis_id": "id_родительской_гипотезы"
  }}
]
```

Сгенерируй 3-5 follow-up гипотез. Только JSON."""

        try:
            messages = [
                {"role": "system", "content": "Ты — эксперт по пентесту. Отвечай только валидным JSON."},
                {"role": "user", "content": prompt},
            ]
            response = self._llm.complete(messages)
            hypotheses = self._parse_hypotheses_response(response.content, scan_id, iteration)

            logger.info("Generated %d follow-up hypotheses for iteration %d", len(hypotheses), iteration)
            return hypotheses

        except Exception as e:
            logger.error("Failed to generate follow-up hypotheses: %s", e)
            return []

    def create_request(self, hypothesis: TestHypothesis) -> AIRequest:
        """Создаёт HTTP-запрос для проверки гипотезы.

        Args:
            hypothesis: гипотеза для проверки.

        Returns:
            AI-сгенерированный HTTP-запрос.
        """
        prompt = f"""Сгенерируй HTTP-запрос для проверки гипотезы об уязвимости.

## Гипотеза
Тип: {hypothesis.vulnerability_type}
Описание: {hypothesis.description}
Обоснование: {hypothesis.rationale}
Целевой URL: {hypothesis.target_url}

## Задача
Сгенерируй конкретный HTTP-запрос для проверки этой гипотезы.
Запрос должен быть READ-ONLY (не модифицировать данные).

## Формат ответа (JSON)
```json
{{
  "method": "GET",
  "url": "полный URL с payload",
  "headers": {{"User-Agent": "Mozilla/5.0", "Accept": "*/*"}},
  "body": null,
  "expected_indicators": ["root:", "/etc/passwd", "syntax error"]
}}
```

Только JSON, без пояснений."""

        try:
            messages = [
                {"role": "system", "content": "Ты — эксперт по пентесту. Генерируй только read-only запросы. Отвечай валидным JSON."},
                {"role": "user", "content": prompt},
            ]
            response = self._llm.complete(messages)
            request = self._parse_request_response(response.content, hypothesis)

            logger.debug("Created request for hypothesis %s: %s %s", hypothesis.id, request.method, request.url)
            return request

        except Exception as e:
            logger.error("Failed to create request for hypothesis %s: %s", hypothesis.id, e)
            # Возвращаем базовый GET-запрос
            return AIRequest(
                id=uuid.uuid4().hex[:12],
                hypothesis_id=hypothesis.id,
                method="GET",
                url=hypothesis.target_url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
                body=None,
                expected_indicators=[],
                timeout_seconds=30,
                status=AIRequestStatus.PENDING,
                created_at=datetime.now(UTC),
            )

    def _format_technologies(self, fingerprints: list[TechnologyFingerprint]) -> str:
        """Форматирует технологии для промпта."""
        if not fingerprints:
            return "Технологии не обнаружены."

        lines = []
        for fp in fingerprints:
            version_str = f" v{fp.version}" if fp.version else ""
            cve_str = ""
            if fp.known_cves:
                cve_ids = [cve.cve_id for cve in fp.known_cves[:3]]
                cve_str = f" (CVE: {', '.join(cve_ids)})"
            lines.append(f"- {fp.name}{version_str} [{fp.category.value}]{cve_str}")

        return "\n".join(lines)

    def _format_findings(self, findings: list[RawFinding]) -> str:
        """Форматирует находки Stage 1 для промпта."""
        if not findings:
            return "Находки Stage 1 отсутствуют."

        lines = []
        for f in findings[:20]:  # Ограничиваем количество
            lines.append(f"- [{f.vulnerability_type}] {f.description[:100]}")

        return "\n".join(lines)

    def _format_previous_results(self, results: list[AIRequestResult]) -> str:
        """Форматирует предыдущие результаты для промпта."""
        if not results:
            return "Предыдущие результаты отсутствуют."

        lines = []
        for r in results[-10:]:  # Последние 10
            status = r.status_code or "error"
            body_preview = r.response_body[:200] if r.response_body else "empty"
            lines.append(f"- Request {r.request_id}: status={status}, body_preview={body_preview}")

        return "\n".join(lines)

    def _parse_hypotheses_response(
        self, content: str, scan_id: str, iteration: int = 0
    ) -> list[TestHypothesis]:
        """Парсит JSON-ответ LLM в список гипотез."""
        # Убираем markdown code blocks
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"```(?:json)?\n?", "", content)
            content = content.strip()

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse hypotheses JSON: %s", e)
            return []

        hypotheses = []
        for item in data:
            try:
                hypothesis = TestHypothesis(
                    id=uuid.uuid4().hex[:12],
                    scan_id=scan_id,
                    description=item.get("description", ""),
                    rationale=item.get("rationale", ""),
                    target_url=item.get("target_url", ""),
                    vulnerability_type=item.get("vulnerability_type", "unknown"),
                    severity_estimate=item.get("severity_estimate", "medium"),
                    source_fingerprint_id=item.get("source_fingerprint_id"),
                    source_finding_id=item.get("source_finding_id"),
                    parent_hypothesis_id=item.get("parent_hypothesis_id"),
                    iteration=iteration,
                    status=HypothesisStatus.PENDING,
                    created_at=datetime.now(UTC),
                )
                hypotheses.append(hypothesis)
            except Exception as e:
                logger.warning("Failed to parse hypothesis item: %s", e)
                continue

        return hypotheses

    def _parse_request_response(self, content: str, hypothesis: TestHypothesis) -> AIRequest:
        """Парсит JSON-ответ LLM в AIRequest."""
        # Убираем markdown code blocks
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"```(?:json)?\n?", "", content)
            content = content.strip()

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse request JSON: %s", e)
            raise

        return AIRequest(
            id=uuid.uuid4().hex[:12],
            hypothesis_id=hypothesis.id,
            method=data.get("method", "GET").upper(),
            url=data.get("url", hypothesis.target_url),
            headers=data.get("headers", {}),
            body=data.get("body"),
            expected_indicators=data.get("expected_indicators", []),
            timeout_seconds=30,
            status=AIRequestStatus.PENDING,
            created_at=datetime.now(UTC),
        )

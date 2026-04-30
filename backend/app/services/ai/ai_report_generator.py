"""AIReportGenerator — AI-генерация отчётов через DeepSeek V4-Pro.

Генерирует отчёты человеческого качества с учётом disclosure_requirements,
поддерживает итеративное улучшение и fallback на шаблонный ReportGenerator.
"""

import logging
import uuid
from datetime import UTC, datetime

from app.models.ai_schemas import SessionContext
from app.models.schemas import ParsedProgram, Report, SeverityLevel, Vulnerability
from app.services.ai.llm_provider_manager import LLMProviderManager
from app.services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

REPORT_SYSTEM_PROMPT = """Ты — профессиональный составитель отчётов об уязвимостях.
Сгенерируй качественный отчёт об уязвимости со следующими разделами:
1. Описание — понятное объяснение уязвимости
2. Шаги воспроизведения — подробная пошаговая инструкция
3. Доказательство концепции — техническое подтверждение/код
4. Влияние — оценка влияния на бизнес и безопасность
5. Рекомендации по устранению — рекомендуемые исправления

Отвечай ТОЛЬКО валидным JSON:
{
  "description": "...",
  "steps_to_reproduce": "...",
  "proof_of_concept": "...",
  "impact": "...",
  "remediation": "..."
}

Пиши профессионально. Будь конкретным и подробным. Отвечай на русском языке."""

IMPROVE_SYSTEM_PROMPT = """Ты — профессиональный редактор отчётов об уязвимостях.
Улучши данный отчёт согласно инструкции пользователя.
Верни полный улучшенный отчёт в том же формате JSON:
{
  "description": "...",
  "steps_to_reproduce": "...",
  "proof_of_concept": "...",
  "impact": "...",
  "remediation": "..."
}
Отвечай на русском языке."""


class AIReportGenerator:
    """Генератор отчётов через LLM (DeepSeek V4-Pro)."""

    def __init__(
        self,
        llm_manager: LLMProviderManager,
        report_generator: ReportGenerator | None = None,
    ):
        self._llm = llm_manager
        self._fallback = report_generator or ReportGenerator()

    def generate(
        self,
        vulnerability: Vulnerability,
        program: ParsedProgram,
        context: SessionContext | None = None,
    ) -> Report:
        """Генерирует отчёт через DeepSeek V4-Pro."""
        try:
            vuln_text = (
                f"Type: {vulnerability.vulnerability_type}\n"
                f"Severity: {vulnerability.severity.value if isinstance(vulnerability.severity, SeverityLevel) else vulnerability.severity}\n"
                f"Description: {vulnerability.description}\n"
                f"Evidence: {vulnerability.evidence}\n"
                f"Steps: {vulnerability.steps_to_reproduce}\n"
                f"Impact: {vulnerability.impact_assessment}\n"
                f"Remediation: {vulnerability.remediation}"
            )
            program_text = f"Program: {program.name}\nPlatform: {program.platform}"
            if program.disclosure_requirements:
                program_text += f"\nDisclosure Requirements: {program.disclosure_requirements}"

            messages = [
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": f"{program_text}\n\nVulnerability:\n{vuln_text}"},
            ]
            response = self._llm.complete(messages)
            return self._parse_report(response.content, vulnerability, program)
        except Exception as e:
            logger.warning(f"AI report generation failed, using fallback: {e}")
            return self.fallback_generate(vulnerability, program)

    def improve(
        self,
        report: Report,
        instruction: str,
        context: SessionContext | None = None,
    ) -> Report:
        """Итеративное улучшение отчёта по инструкции пользователя."""
        try:
            report_text = (
                f"Title: {report.title}\n"
                f"Description: {report.description}\n"
                f"Steps to Reproduce: {report.steps_to_reproduce}\n"
                f"Proof of Concept: {report.proof_of_concept}\n"
                f"Impact: {report.impact}\n"
                f"Remediation: {report.remediation}"
            )
            messages = [
                {"role": "system", "content": IMPROVE_SYSTEM_PROMPT},
                {"role": "user", "content": f"Current report:\n{report_text}\n\nInstruction: {instruction}"},
            ]
            response = self._llm.complete_with_pro(messages)
            return self._parse_improved_report(response.content, report)
        except Exception as e:
            logger.warning(f"AI report improvement failed: {e}")
            return report

    def fallback_generate(
        self,
        vulnerability: Vulnerability,
        program: ParsedProgram,
    ) -> Report:
        """Fallback на шаблонный ReportGenerator."""
        return self._fallback.generate(vulnerability, program)

    @staticmethod
    def _parse_report(raw: str, vulnerability: Vulnerability, program: ParsedProgram) -> Report:
        """Parse LLM response into Report."""
        import json

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
        now = datetime.now(UTC)
        severity = vulnerability.severity if isinstance(vulnerability.severity, SeverityLevel) else SeverityLevel(vulnerability.severity)

        return Report(
            id=str(uuid.uuid4()),
            vulnerability_id=vulnerability.id,
            program_id=program.id,
            title=f"[{severity.value.upper()}] {vulnerability.vulnerability_type} — {program.name}",
            description=data.get("description", vulnerability.description),
            steps_to_reproduce=data.get("steps_to_reproduce", vulnerability.steps_to_reproduce),
            proof_of_concept=data.get("proof_of_concept", vulnerability.evidence),
            impact=data.get("impact", vulnerability.impact_assessment),
            severity=severity,
            remediation=data.get("remediation", vulnerability.remediation),
            format_version="2.0-ai",
            created_at=now,
            updated_at=now,
        )

    @staticmethod
    def _parse_improved_report(raw: str, original: Report) -> Report:
        """Parse improved report from LLM response."""
        import json

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
        now = datetime.now(UTC)

        return Report(
            id=original.id,
            vulnerability_id=original.vulnerability_id,
            program_id=original.program_id,
            title=original.title,
            description=data.get("description", original.description),
            steps_to_reproduce=data.get("steps_to_reproduce", original.steps_to_reproduce),
            proof_of_concept=data.get("proof_of_concept", original.proof_of_concept),
            impact=data.get("impact", original.impact),
            severity=original.severity,
            remediation=data.get("remediation", original.remediation),
            format_version=original.format_version,
            created_at=original.created_at,
            updated_at=now,
        )

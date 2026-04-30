"""Генератор отчётов об уязвимостях.

Содержит класс ReportGenerator для:
- Генерации структурированных отчётов из уязвимостей
- Экспорта в Markdown и PDF (text-based)
- Валидации полноты данных

Требования: 6.1, 6.2, 6.3, 6.4
"""

import uuid
from datetime import UTC, datetime

from app.core.exceptions import InsufficientDataError
from app.models.schemas import ParsedProgram, Report, SeverityLevel, Vulnerability


class ReportGenerator:
    """Генератор отчётов об уязвимостях."""

    # Обязательные поля уязвимости для генерации отчёта
    REQUIRED_FIELDS = [
        "description",
        "steps_to_reproduce",
        "evidence",
        "impact_assessment",
        "remediation",
    ]

    def generate(self, vulnerability: Vulnerability, program: ParsedProgram) -> Report:
        """Генерирует структурированный отчёт.

        Args:
            vulnerability: данные об уязвимости
            program: программа (для формата отчёта)

        Returns:
            Report с описанием, шагами воспроизведения, PoC, рекомендациями

        Raises:
            InsufficientDataError: если данных недостаточно для отчёта
        """
        missing = self.validate_completeness(vulnerability)
        if missing:
            raise InsufficientDataError(missing)

        now = datetime.now(UTC)

        title = f"[{vulnerability.severity.value.upper()}] {vulnerability.vulnerability_type}"
        if program.name:
            title = f"{title} — {program.name}"

        description = vulnerability.description
        if program.disclosure_requirements:
            description += f"\n\nDisclosure requirements: {program.disclosure_requirements}"

        return Report(
            id=str(uuid.uuid4()),
            vulnerability_id=vulnerability.id,
            program_id=program.id,
            title=title,
            description=description,
            steps_to_reproduce=vulnerability.steps_to_reproduce,
            proof_of_concept=vulnerability.evidence,
            impact=vulnerability.impact_assessment,
            severity=vulnerability.severity,
            remediation=vulnerability.remediation,
            format_version="1.0",
            created_at=now,
            updated_at=now,
        )

    def export_markdown(self, report: Report) -> str:
        """Экспорт отчёта в Markdown.

        Args:
            report: отчёт для экспорта

        Returns:
            Строка в формате Markdown
        """
        lines = [
            f"# {report.title}",
            "",
            f"**Серьёзность:** {report.severity.value.upper()}",
            f"**ID отчёта:** {report.id}",
            f"**Создан:** {report.created_at.isoformat()}",
            "",
            "## Описание",
            "",
            report.description,
            "",
            "## Шаги для воспроизведения",
            "",
            report.steps_to_reproduce,
            "",
            "## Доказательство концепции",
            "",
            report.proof_of_concept,
            "",
            "## Влияние",
            "",
            report.impact,
            "",
            "## Рекомендации по устранению",
            "",
            report.remediation,
            "",
        ]
        return "\n".join(lines)

    def export_pdf(self, report: Report) -> bytes:
        """Экспорт отчёта в PDF (text-based representation).

        Генерирует простое текстовое представление, закодированное в bytes.

        Args:
            report: отчёт для экспорта

        Returns:
            bytes — текстовое представление отчёта
        """
        text = (
            f"ОТЧЁТ ОБ УЯЗВИМОСТИ\n"
            f"{'=' * 40}\n"
            f"Название: {report.title}\n"
            f"Серьёзность: {report.severity.value.upper()}\n"
            f"ID отчёта: {report.id}\n"
            f"Создан: {report.created_at.isoformat()}\n"
            f"\n"
            f"ОПИСАНИЕ\n{'-' * 40}\n{report.description}\n\n"
            f"ШАГИ ДЛЯ ВОСПРОИЗВЕДЕНИЯ\n{'-' * 40}\n{report.steps_to_reproduce}\n\n"
            f"ДОКАЗАТЕЛЬСТВО КОНЦЕПЦИИ\n{'-' * 40}\n{report.proof_of_concept}\n\n"
            f"ВЛИЯНИЕ\n{'-' * 40}\n{report.impact}\n\n"
            f"РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ\n{'-' * 40}\n{report.remediation}\n"
        )
        return text.encode("utf-8")

    def validate_completeness(self, vulnerability: Vulnerability) -> list[str]:
        """Проверяет полноту данных для отчёта.

        Args:
            vulnerability: уязвимость для проверки

        Returns:
            Список недостающих полей (пустой если всё заполнено)
        """
        missing: list[str] = []
        for field in self.REQUIRED_FIELDS:
            value = getattr(vulnerability, field, None)
            if not value or (isinstance(value, str) and not value.strip()):
                missing.append(field)
        return missing

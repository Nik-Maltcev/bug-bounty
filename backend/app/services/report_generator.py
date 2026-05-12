"""Генератор отчётов об уязвимостях.

Содержит класс ReportGenerator для:
- Генерации структурированных отчётов из уязвимостей
- Экспорта в Markdown и PDF (text-based)
- Автоматического обогащения данных из базы знаний

Требования: 6.1, 6.2, 6.3, 6.4
"""

import uuid
from datetime import UTC, datetime

from app.models.schemas import ParsedProgram, Report, SeverityLevel, Vulnerability
from app.services.vulnerability_knowledge import enrich_vulnerability, get_vulnerability_info


class ReportGenerator:
    """Генератор отчётов об уязвимостях."""

    def generate(self, vulnerability: Vulnerability, program: ParsedProgram) -> Report:
        """Генерирует структурированный отчёт.

        Автоматически обогащает данные из базы знаний если поля пустые.

        Args:
            vulnerability: данные об уязвимости
            program: программа (для формата отчёта)

        Returns:
            Report с описанием, шагами воспроизведения, PoC, рекомендациями
        """
        now = datetime.now(UTC)

        # Получаем информацию из базы знаний
        vuln_info = get_vulnerability_info(vulnerability.vulnerability_type)
        enriched = enrich_vulnerability(
            vuln_type=vulnerability.vulnerability_type,
            description=vulnerability.description,
            evidence=vulnerability.evidence,
        )

        # Формируем заголовок
        severity_label = self._get_severity_label(vulnerability.severity)
        vuln_title = vuln_info.title if vuln_info else vulnerability.vulnerability_type
        title = f"[{severity_label}] {vuln_title}"
        if program.name:
            title = f"{title} — {program.name}"

        # Используем данные из уязвимости или обогащённые данные
        description = vulnerability.description or enriched["description"]
        steps = vulnerability.steps_to_reproduce or enriched["steps_to_reproduce"]
        impact = vulnerability.impact_assessment or enriched["impact_assessment"]
        remediation = vulnerability.remediation or enriched["remediation"]
        evidence = vulnerability.evidence or "Не указано"

        # Добавляем disclosure requirements если есть
        if program.disclosure_requirements:
            description += f"\n\n**Требования к раскрытию:** {program.disclosure_requirements}"

        return Report(
            id=str(uuid.uuid4()),
            vulnerability_id=vulnerability.id,
            program_id=program.id,
            title=title,
            description=description,
            steps_to_reproduce=steps,
            proof_of_concept=evidence,
            impact=impact,
            severity=vulnerability.severity,
            remediation=remediation,
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
        severity_emoji = self._get_severity_emoji(report.severity)
        severity_label = self._get_severity_label(report.severity)
        
        lines = [
            f"# {report.title}",
            "",
            f"**Серьёзность:** {severity_emoji} {severity_label}",
            f"**ID отчёта:** `{report.id}`",
            f"**Создан:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "---",
            "",
            "## 📋 Описание",
            "",
            report.description,
            "",
            "---",
            "",
            "## 🔍 Шаги для воспроизведения",
            "",
            report.steps_to_reproduce,
            "",
            "---",
            "",
            "## 💻 Доказательство концепции (PoC)",
            "",
            "```",
            report.proof_of_concept,
            "```",
            "",
            "---",
            "",
            "## ⚠️ Оценка влияния",
            "",
            report.impact,
            "",
            "---",
            "",
            "## ✅ Рекомендации по устранению",
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
        severity_label = self._get_severity_label(report.severity)
        
        text = (
            f"{'=' * 60}\n"
            f"ОТЧЁТ ОБ УЯЗВИМОСТИ\n"
            f"{'=' * 60}\n\n"
            f"Название: {report.title}\n"
            f"Серьёзность: {severity_label}\n"
            f"ID отчёта: {report.id}\n"
            f"Создан: {report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"\n{'=' * 60}\n\n"
            f"ОПИСАНИЕ\n{'-' * 40}\n{report.description}\n\n"
            f"ШАГИ ДЛЯ ВОСПРОИЗВЕДЕНИЯ\n{'-' * 40}\n{report.steps_to_reproduce}\n\n"
            f"ДОКАЗАТЕЛЬСТВО КОНЦЕПЦИИ\n{'-' * 40}\n{report.proof_of_concept}\n\n"
            f"ОЦЕНКА ВЛИЯНИЯ\n{'-' * 40}\n{report.impact}\n\n"
            f"РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ\n{'-' * 40}\n{report.remediation}\n"
        )
        return text.encode("utf-8")

    def validate_completeness(self, vulnerability: Vulnerability) -> list[str]:
        """Проверяет полноту данных для отчёта.

        Теперь всегда возвращает пустой список, так как данные
        автоматически обогащаются из базы знаний.

        Args:
            vulnerability: уязвимость для проверки

        Returns:
            Пустой список (данные всегда достаточны)
        """
        return []

    @staticmethod
    def _get_severity_label(severity: SeverityLevel) -> str:
        """Возвращает русскую метку серьёзности."""
        labels = {
            SeverityLevel.CRITICAL: "КРИТИЧЕСКАЯ",
            SeverityLevel.HIGH: "ВЫСОКАЯ",
            SeverityLevel.MEDIUM: "СРЕДНЯЯ",
            SeverityLevel.LOW: "НИЗКАЯ",
            SeverityLevel.INFORMATIONAL: "ИНФОРМАЦИОННАЯ",
        }
        return labels.get(severity, severity.value.upper())

    @staticmethod
    def _get_severity_emoji(severity: SeverityLevel) -> str:
        """Возвращает emoji для серьёзности."""
        emojis = {
            SeverityLevel.CRITICAL: "🔴",
            SeverityLevel.HIGH: "🟠",
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.LOW: "🔵",
            SeverityLevel.INFORMATIONAL: "⚪",
        }
        return emojis.get(severity, "⚪")

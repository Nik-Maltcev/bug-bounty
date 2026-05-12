"""Тесты для ReportGenerator.

Покрывает задачи 8.1, 8.2:
- generate() — генерация структурированного отчёта
- export_markdown() — экспорт в Markdown
- export_pdf() — экспорт в PDF (text-based)
- validate_completeness() — валидация полноты данных
"""

from datetime import UTC, datetime

import pytest

from app.models.schemas import (
    Asset,
    AssetType,
    ParsedProgram,
    Report,
    SeverityLevel,
    Vulnerability,
)
from app.services.report_generator import ReportGenerator


@pytest.fixture()
def generator():
    return ReportGenerator()


@pytest.fixture()
def sample_program():
    return ParsedProgram(
        id="prog-1",
        name="Test Program",
        platform="hackerone",
        assets=[
            Asset(
                id="asset-1",
                name="Web App",
                asset_type=AssetType.WEB_APPLICATION,
                target="https://example.com",
            )
        ],
        rules=[],
        reward_tiers=[],
        disclosure_requirements="Responsible disclosure within 90 days",
        raw_text="",
        created_at=datetime.now(UTC),
    )


@pytest.fixture()
def full_vulnerability():
    return Vulnerability(
        id="vuln-1",
        scan_id="scan-1",
        program_id="prog-1",
        vulnerability_type="XSS",
        severity=SeverityLevel.HIGH,
        description="Reflected XSS in search parameter",
        steps_to_reproduce="1. Go to /search\n2. Enter <script>alert(1)</script>",
        evidence="<script>alert(1)</script> executed in browser",
        affected_asset=Asset(
            id="asset-1",
            name="Web App",
            asset_type=AssetType.WEB_APPLICATION,
            target="https://example.com",
        ),
        impact_assessment="Attacker can execute arbitrary JavaScript",
        remediation="Sanitize user input in search parameter",
        status="new",
        created_at=datetime.now(UTC),
    )


@pytest.fixture()
def incomplete_vulnerability():
    return Vulnerability(
        id="vuln-2",
        scan_id="scan-1",
        program_id="prog-1",
        vulnerability_type="SQLi",
        severity=SeverityLevel.CRITICAL,
        description="SQL injection found",
        steps_to_reproduce="",
        evidence="",
        affected_asset=Asset(
            id="asset-1",
            name="Web App",
            asset_type=AssetType.WEB_APPLICATION,
            target="https://example.com",
        ),
        impact_assessment="",
        remediation="",
        status="new",
        created_at=datetime.now(UTC),
    )


class TestGenerate:
    """Тесты generate()."""

    def test_generate_success(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        assert isinstance(report, Report)
        assert report.vulnerability_id == "vuln-1"
        assert report.program_id == "prog-1"
        assert report.severity == SeverityLevel.HIGH
        assert "XSS" in report.title
        assert "Test Program" in report.title
        assert report.description
        assert report.steps_to_reproduce
        assert report.proof_of_concept
        assert report.impact
        assert report.remediation

    def test_generate_includes_disclosure_requirements(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        assert "Responsible disclosure" in report.description

    def test_generate_with_incomplete_data_uses_knowledge_base(self, generator, incomplete_vulnerability, sample_program):
        """Теперь генератор автоматически обогащает данные из базы знаний."""
        report = generator.generate(incomplete_vulnerability, sample_program)
        assert isinstance(report, Report)
        # Данные должны быть заполнены из базы знаний
        assert report.steps_to_reproduce
        assert report.impact
        assert report.remediation

    def test_generate_format_version(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        assert report.format_version == "1.0"


class TestExportMarkdown:
    """Тесты export_markdown()."""

    def test_export_markdown_contains_sections(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        md = generator.export_markdown(report)
        assert "# " in md
        # Проверяем наличие секций (с emoji)
        assert "Описание" in md
        assert "Шаги для воспроизведения" in md
        assert "Доказательство концепции" in md or "PoC" in md
        assert "Влияние" in md or "влияния" in md
        assert "Рекомендации" in md

    def test_export_markdown_contains_content(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        md = generator.export_markdown(report)
        assert "Reflected XSS" in md
        # Серьёзность теперь на русском
        assert "ВЫСОКАЯ" in md or "HIGH" in md
        assert report.id in md

    def test_export_markdown_returns_string(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        md = generator.export_markdown(report)
        assert isinstance(md, str)
        assert len(md) > 0


class TestExportPdf:
    """Тесты export_pdf()."""

    def test_export_pdf_returns_bytes(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        pdf = generator.export_pdf(report)
        assert isinstance(pdf, bytes)
        assert len(pdf) > 0

    def test_export_pdf_contains_content(self, generator, full_vulnerability, sample_program):
        report = generator.generate(full_vulnerability, sample_program)
        pdf = generator.export_pdf(report)
        text = pdf.decode("utf-8")
        assert "ОТЧЁТ ОБ УЯЗВИМОСТИ" in text
        assert "Reflected XSS" in text
        # Серьёзность теперь на русском
        assert "ВЫСОКАЯ" in text or "HIGH" in text


class TestValidateCompleteness:
    """Тесты validate_completeness()."""

    def test_complete_vulnerability_returns_empty(self, generator, full_vulnerability):
        missing = generator.validate_completeness(full_vulnerability)
        assert missing == []

    def test_incomplete_vulnerability_returns_empty_with_knowledge_base(self, generator, incomplete_vulnerability):
        """Теперь validate_completeness всегда возвращает пустой список,
        так как данные автоматически обогащаются из базы знаний."""
        missing = generator.validate_completeness(incomplete_vulnerability)
        assert missing == []

    def test_whitespace_only_fields_returns_empty(self, generator):
        """Теперь validate_completeness всегда возвращает пустой список."""
        vuln = Vulnerability(
            id="vuln-3",
            scan_id="scan-1",
            program_id="prog-1",
            vulnerability_type="CSRF",
            severity=SeverityLevel.MEDIUM,
            description="   ",
            steps_to_reproduce="Step 1",
            evidence="Evidence here",
            affected_asset=Asset(
                id="a1",
                name="App",
                asset_type=AssetType.WEB_APPLICATION,
                target="https://example.com",
            ),
            impact_assessment="Impact",
            remediation="Fix it",
            status="new",
            created_at=datetime.now(UTC),
        )
        missing = generator.validate_completeness(vuln)
        assert missing == []

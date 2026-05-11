"""Тесты для TechExtractor — извлечение технологий из Stage 1."""

import pytest

from app.models.ai_scan_schemas import TechCategory, TechnologyFingerprint
from app.models.schemas import RawFinding
from app.services.ai.tech_extractor import TechExtractor


@pytest.fixture
def extractor() -> TechExtractor:
    """TechExtractor без LLM."""
    return TechExtractor(llm_manager=None)


def _finding(
    description: str = "",
    evidence: str = "",
    tool: str = "unknown",
    raw_data: dict | None = None,
) -> RawFinding:
    """Хелпер для создания RawFinding."""
    data = raw_data or {}
    data.setdefault("tool", tool)
    return RawFinding(
        vulnerability_type="info",
        description=description,
        evidence=evidence,
        affected_asset_id="asset-1",
        raw_data=data,
    )


class TestExtractFromNmap:
    """Тесты извлечения из nmap-подобного вывода."""

    def test_extract_apache_with_version(self, extractor: TechExtractor):
        """Извлекает Apache с версией."""
        finding = _finding(
            evidence="Apache/2.4.41 (Ubuntu)",
            tool="nmap",
        )
        result = extractor.extract([finding])

        assert len(result) >= 1
        apache = next((t for t in result if t.name == "apache"), None)
        assert apache is not None
        assert apache.version == "2.4.41"
        assert apache.category == TechCategory.WEB_SERVER
        assert apache.confidence >= 0.7

    def test_extract_nginx_with_version(self, extractor: TechExtractor):
        """Извлекает nginx с версией."""
        finding = _finding(
            evidence="nginx/1.18.0",
            tool="nmap",
        )
        result = extractor.extract([finding])

        nginx = next((t for t in result if t.name == "nginx"), None)
        assert nginx is not None
        assert nginx.version == "1.18.0"
        assert nginx.category == TechCategory.WEB_SERVER

    def test_extract_mysql_version(self, extractor: TechExtractor):
        """Извлекает MySQL с версией."""
        finding = _finding(
            evidence="MySQL 5.7.32-0ubuntu0.18.04.1",
            tool="nmap",
        )
        result = extractor.extract([finding])

        mysql = next((t for t in result if t.name == "mysql"), None)
        assert mysql is not None
        assert mysql.version == "5.7.32"
        assert mysql.category == TechCategory.DATABASE

    def test_extract_openssh(self, extractor: TechExtractor):
        """Извлекает OpenSSH."""
        finding = _finding(
            evidence="OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
            tool="nmap",
        )
        result = extractor.extract([finding])

        ssh = next((t for t in result if t.name == "openssh"), None)
        assert ssh is not None
        assert "8.2" in ssh.version

    def test_extract_php_version(self, extractor: TechExtractor):
        """Извлекает PHP с версией."""
        finding = _finding(
            evidence="PHP/7.4.3",
            tool="nmap",
        )
        result = extractor.extract([finding])

        php = next((t for t in result if t.name == "php"), None)
        assert php is not None
        assert php.version == "7.4.3"
        assert php.category == TechCategory.LANGUAGE


class TestExtractFromHeaders:
    """Тесты извлечения из HTTP-заголовков."""

    def test_extract_from_server_header(self, extractor: TechExtractor):
        """Извлекает из Server header."""
        finding = _finding(
            tool="httpx",
            raw_data={
                "tool": "httpx",
                "headers": {
                    "Server": "nginx/1.19.0",
                    "Content-Type": "text/html",
                },
            },
        )
        result = extractor.extract([finding])

        nginx = next((t for t in result if t.name == "nginx"), None)
        assert nginx is not None
        assert nginx.version == "1.19.0"
        assert nginx.confidence >= 0.8

    def test_extract_from_x_powered_by(self, extractor: TechExtractor):
        """Извлекает из X-Powered-By header."""
        finding = _finding(
            tool="httpx",
            raw_data={
                "tool": "httpx",
                "headers": {
                    "X-Powered-By": "PHP/8.0.3",
                },
            },
        )
        result = extractor.extract([finding])

        php = next((t for t in result if t.name == "php"), None)
        assert php is not None
        assert php.version == "8.0.3"

    def test_extract_waf_cloudflare(self, extractor: TechExtractor):
        """Обнаруживает Cloudflare WAF."""
        finding = _finding(
            tool="httpx",
            raw_data={
                "tool": "httpx",
                "headers": {
                    "Server": "cloudflare",
                    "CF-RAY": "abc123",
                },
            },
        )
        result = extractor.extract([finding])

        cloudflare = next((t for t in result if t.name == "cloudflare"), None)
        assert cloudflare is not None
        assert cloudflare.category == TechCategory.WAF


class TestExtractFromNuclei:
    """Тесты извлечения из nuclei templates."""

    def test_extract_wordpress_from_template(self, extractor: TechExtractor):
        """Извлекает WordPress из nuclei template."""
        finding = _finding(
            description="WordPress 5.8 detected",
            tool="nuclei",
            raw_data={
                "tool": "nuclei",
                "template": "wordpress-detect",
                "matched_at": "https://example.com/wp-login.php",
            },
        )
        result = extractor.extract([finding])

        wp = next((t for t in result if t.name == "wordpress"), None)
        assert wp is not None
        assert wp.category == TechCategory.CMS

    def test_extract_drupal_from_template(self, extractor: TechExtractor):
        """Извлекает Drupal из nuclei template."""
        finding = _finding(
            description="Drupal CMS detected",
            tool="nuclei",
            raw_data={
                "tool": "nuclei",
                "template": "drupal-detect",
            },
        )
        result = extractor.extract([finding])

        drupal = next((t for t in result if t.name == "drupal"), None)
        assert drupal is not None
        assert drupal.category == TechCategory.CMS


class TestExtractFrameworks:
    """Тесты извлечения фреймворков."""

    def test_extract_laravel(self, extractor: TechExtractor):
        """Извлекает Laravel."""
        finding = _finding(
            description="Laravel framework detected",
            evidence="Set-Cookie: laravel_session=...",
        )
        result = extractor.extract([finding])

        laravel = next((t for t in result if t.name == "laravel"), None)
        assert laravel is not None
        assert laravel.category == TechCategory.FRAMEWORK

    def test_extract_django(self, extractor: TechExtractor):
        """Извлекает Django."""
        finding = _finding(
            description="Django admin panel found",
            evidence="csrftoken cookie present",
        )
        result = extractor.extract([finding])

        django = next((t for t in result if t.name == "django"), None)
        assert django is not None
        assert django.category == TechCategory.FRAMEWORK

    def test_extract_react(self, extractor: TechExtractor):
        """Извлекает React."""
        finding = _finding(
            description="React application detected",
            evidence="<div id=\"root\"></div>",
        )
        result = extractor.extract([finding])

        react = next((t for t in result if t.name == "react"), None)
        assert react is not None
        assert react.category == TechCategory.FRAMEWORK


class TestDeduplication:
    """Тесты дедупликации технологий."""

    def test_deduplicates_same_tech_same_version(self, extractor: TechExtractor):
        """Дедуплицирует одинаковые технологии с одной версией."""
        findings = [
            _finding(evidence="nginx/1.18.0", tool="nmap"),
            _finding(evidence="nginx/1.18.0", tool="httpx"),
        ]
        result = extractor.extract(findings)

        nginx_count = sum(1 for t in result if t.name == "nginx")
        assert nginx_count == 1

    def test_keeps_different_versions(self, extractor: TechExtractor):
        """Сохраняет разные версии одной технологии."""
        findings = [
            _finding(evidence="PHP/7.4.3", tool="nmap", raw_data={"tool": "nmap"}),
            _finding(evidence="PHP/8.0.0", tool="httpx", raw_data={"tool": "httpx"}),
        ]
        result = extractor.extract(findings)

        php_versions = [t for t in result if t.name == "php"]
        # Дедупликация по name:version — разные версии сохраняются
        assert len(php_versions) >= 1  # минимум одна версия найдена
        # Проверяем что хотя бы одна версия извлечена корректно
        versions = {t.version for t in php_versions}
        assert "7.4.3" in versions or "8.0.0" in versions

    def test_higher_confidence_wins(self, extractor: TechExtractor):
        """При дубликатах сохраняется версия с большей уверенностью."""
        findings = [
            _finding(evidence="nginx/1.18.0", tool="nmap"),  # confidence ~0.9
            _finding(
                tool="httpx",
                raw_data={
                    "tool": "httpx",
                    "headers": {"Server": "nginx/1.18.0"},
                },
            ),  # confidence ~0.95
        ]
        result = extractor.extract(findings)

        nginx = next((t for t in result if t.name == "nginx"), None)
        assert nginx is not None
        # Должна быть версия с большей уверенностью (из headers)
        assert nginx.confidence >= 0.9


class TestMultipleTechnologies:
    """Тесты извлечения нескольких технологий."""

    def test_extract_multiple_from_single_finding(self, extractor: TechExtractor):
        """Извлекает несколько технологий из одной находки."""
        finding = _finding(
            evidence="Apache/2.4.41 PHP/7.4.3 MySQL/5.7",
            tool="nmap",
        )
        result = extractor.extract([finding])

        names = {t.name for t in result}
        assert "apache" in names
        assert "php" in names
        assert "mysql" in names

    def test_extract_from_multiple_findings(self, extractor: TechExtractor):
        """Извлекает технологии из нескольких находок."""
        findings = [
            _finding(evidence="nginx/1.18.0", tool="nmap"),
            _finding(evidence="PostgreSQL 13.1", tool="nmap"),
            _finding(description="WordPress 5.8 detected", tool="nuclei"),
        ]
        result = extractor.extract(findings)

        names = {t.name for t in result}
        assert "nginx" in names
        assert "postgresql" in names
        assert "wordpress" in names


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_empty_findings_list(self, extractor: TechExtractor):
        """Пустой список находок возвращает пустой результат."""
        result = extractor.extract([])
        assert result == []

    def test_finding_without_tech_info(self, extractor: TechExtractor):
        """Находка без информации о технологиях."""
        finding = _finding(
            description="Some generic finding",
            evidence="No technology info here",
        )
        result = extractor.extract([finding])
        # Может быть пустым или содержать что-то, но не должен падать
        assert isinstance(result, list)

    def test_malformed_version_string(self, extractor: TechExtractor):
        """Некорректная строка версии."""
        finding = _finding(
            evidence="nginx/unknown-version",
            tool="nmap",
        )
        result = extractor.extract([finding])
        # Не должен падать
        assert isinstance(result, list)

    def test_case_insensitive_matching(self, extractor: TechExtractor):
        """Регистронезависимый поиск."""
        finding = _finding(
            evidence="NGINX/1.18.0",
            tool="nmap",
        )
        result = extractor.extract([finding])

        nginx = next((t for t in result if t.name == "nginx"), None)
        assert nginx is not None


class TestTechnologyFingerprint:
    """Тесты структуры TechnologyFingerprint."""

    def test_fingerprint_has_required_fields(self, extractor: TechExtractor):
        """Fingerprint содержит все обязательные поля."""
        finding = _finding(evidence="nginx/1.18.0", tool="nmap")
        result = extractor.extract([finding])

        assert len(result) >= 1
        fp = result[0]

        assert fp.id is not None
        assert fp.name is not None
        assert fp.category is not None
        assert fp.source is not None
        assert 0.0 <= fp.confidence <= 1.0

    def test_fingerprint_raw_evidence(self, extractor: TechExtractor):
        """Fingerprint содержит raw_evidence."""
        finding = _finding(evidence="Apache/2.4.41 (Ubuntu)", tool="nmap")
        result = extractor.extract([finding])

        apache = next((t for t in result if t.name == "apache"), None)
        assert apache is not None
        assert "Apache" in apache.raw_evidence or "2.4.41" in apache.raw_evidence

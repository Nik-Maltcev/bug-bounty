"""Плагин сканирования веб-приложений.

Выполняет проверки на типичные веб-уязвимости:
- XSS (Cross-Site Scripting)
- SQL Injection
- CSRF (Cross-Site Request Forgery)
- Open Redirect
- Security Headers
"""

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig
from app.services.scan_plugins.base import ScanPlugin


class WebScanPlugin(ScanPlugin):
    """Плагин сканирования веб-приложений."""

    CHECK_NAMES = [
        "xss_check",
        "sql_injection_check",
        "csrf_check",
        "open_redirect_check",
        "security_headers_check",
    ]

    def get_asset_type(self) -> AssetType:
        return AssetType.WEB_APPLICATION

    def get_check_names(self) -> list[str]:
        return list(self.CHECK_NAMES)

    def scan(self, asset: Asset, config: ScanConfig) -> list[RawFinding]:
        """Выполняет набор проверок веб-безопасности.

        MVP-реализация: возвращает симулированные находки
        на основе типа проверки и целевого URL.
        """
        findings: list[RawFinding] = []
        checks = config.check_types if config.check_types else self.CHECK_NAMES

        for check in checks:
            if check not in self.CHECK_NAMES:
                continue
            finding = self._run_check(check, asset)
            if finding:
                findings.append(finding)

        return findings

    def _run_check(self, check: str, asset: Asset) -> RawFinding | None:
        """Запускает одну проверку. MVP: симуляция находок."""
        check_map = {
            "xss_check": self._check_xss,
            "sql_injection_check": self._check_sql_injection,
            "csrf_check": self._check_csrf,
            "open_redirect_check": self._check_open_redirect,
            "security_headers_check": self._check_security_headers,
        }
        handler = check_map.get(check)
        if handler:
            return handler(asset)
        return None

    @staticmethod
    def _check_xss(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="xss",
            description=f"Potential reflected XSS found on {asset.target}",
            evidence=f"Input parameter 'q' on {asset.target}/search is reflected without encoding",
            affected_asset_id=asset.id,
            raw_data={"check": "xss_check", "target": asset.target},
        )

    @staticmethod
    def _check_sql_injection(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="sql_injection",
            description=f"Potential SQL injection on {asset.target}",
            evidence=f"Parameter 'id' on {asset.target}/api/items responds differently to SQL payloads",
            affected_asset_id=asset.id,
            raw_data={"check": "sql_injection_check", "target": asset.target},
        )

    @staticmethod
    def _check_csrf(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="csrf",
            description=f"Missing CSRF protection on {asset.target}",
            evidence=f"Form on {asset.target}/settings lacks CSRF token",
            affected_asset_id=asset.id,
            raw_data={"check": "csrf_check", "target": asset.target},
        )

    @staticmethod
    def _check_open_redirect(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="open_redirect",
            description=f"Open redirect vulnerability on {asset.target}",
            evidence=f"Parameter 'next' on {asset.target}/login allows external redirect",
            affected_asset_id=asset.id,
            raw_data={"check": "open_redirect_check", "target": asset.target},
        )

    @staticmethod
    def _check_security_headers(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="missing_security_headers",
            description=f"Missing security headers on {asset.target}",
            evidence=f"Headers X-Frame-Options, Content-Security-Policy not set on {asset.target}",
            affected_asset_id=asset.id,
            raw_data={"check": "security_headers_check", "target": asset.target},
        )

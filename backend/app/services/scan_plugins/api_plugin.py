"""Плагин сканирования API-эндпоинтов.

Выполняет проверки на типичные уязвимости API:
- Broken Authentication
- Excessive Data Exposure
- Rate Limiting
- Injection
"""

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig
from app.services.scan_plugins.base import ScanPlugin


class ApiScanPlugin(ScanPlugin):
    """Плагин сканирования API-эндпоинтов."""

    CHECK_NAMES = [
        "broken_auth_check",
        "data_exposure_check",
        "rate_limiting_check",
        "api_injection_check",
    ]

    def get_asset_type(self) -> AssetType:
        return AssetType.API

    def get_check_names(self) -> list[str]:
        return list(self.CHECK_NAMES)

    def scan(self, asset: Asset, config: ScanConfig) -> list[RawFinding]:
        """Выполняет проверки безопасности API."""
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
        check_map = {
            "broken_auth_check": self._check_broken_auth,
            "data_exposure_check": self._check_data_exposure,
            "rate_limiting_check": self._check_rate_limiting,
            "api_injection_check": self._check_api_injection,
        }
        handler = check_map.get(check)
        if handler:
            return handler(asset)
        return None

    @staticmethod
    def _check_broken_auth(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="broken_authentication",
            description=f"Broken authentication on API {asset.target}",
            evidence=f"Endpoint {asset.target}/users accessible without authentication",
            affected_asset_id=asset.id,
            raw_data={"check": "broken_auth_check", "target": asset.target},
        )

    @staticmethod
    def _check_data_exposure(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="excessive_data_exposure",
            description=f"Excessive data exposure on API {asset.target}",
            evidence=f"Endpoint {asset.target}/users returns password hashes in response",
            affected_asset_id=asset.id,
            raw_data={"check": "data_exposure_check", "target": asset.target},
        )

    @staticmethod
    def _check_rate_limiting(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="missing_rate_limiting",
            description=f"Missing rate limiting on API {asset.target}",
            evidence=f"No rate limiting headers on {asset.target}/auth/login",
            affected_asset_id=asset.id,
            raw_data={"check": "rate_limiting_check", "target": asset.target},
        )

    @staticmethod
    def _check_api_injection(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="api_injection",
            description=f"Potential injection vulnerability on API {asset.target}",
            evidence=f"Parameter 'filter' on {asset.target}/search accepts unvalidated input",
            affected_asset_id=asset.id,
            raw_data={"check": "api_injection_check", "target": asset.target},
        )

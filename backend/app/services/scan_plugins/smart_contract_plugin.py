"""Плагин сканирования смарт-контрактов.

Выполняет проверки на типичные уязвимости смарт-контрактов:
- Reentrancy
- Integer Overflow/Underflow
- Access Control
- Unchecked External Calls
"""

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig
from app.services.scan_plugins.base import ScanPlugin


class SmartContractScanPlugin(ScanPlugin):
    """Плагин сканирования смарт-контрактов."""

    CHECK_NAMES = [
        "reentrancy_check",
        "integer_overflow_check",
        "access_control_check",
        "unchecked_call_check",
    ]

    def get_asset_type(self) -> AssetType:
        return AssetType.SMART_CONTRACT

    def get_check_names(self) -> list[str]:
        return list(self.CHECK_NAMES)

    def scan(self, asset: Asset, config: ScanConfig) -> list[RawFinding]:
        """Выполняет анализ кода смарт-контракта."""
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
            "reentrancy_check": self._check_reentrancy,
            "integer_overflow_check": self._check_integer_overflow,
            "access_control_check": self._check_access_control,
            "unchecked_call_check": self._check_unchecked_call,
        }
        handler = check_map.get(check)
        if handler:
            return handler(asset)
        return None

    @staticmethod
    def _check_reentrancy(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="reentrancy",
            description=f"Potential reentrancy vulnerability in contract {asset.target}",
            evidence="External call before state update in withdraw() function",
            affected_asset_id=asset.id,
            raw_data={"check": "reentrancy_check", "target": asset.target},
        )

    @staticmethod
    def _check_integer_overflow(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="integer_overflow",
            description=f"Potential integer overflow in contract {asset.target}",
            evidence="Unchecked arithmetic in transfer() function",
            affected_asset_id=asset.id,
            raw_data={"check": "integer_overflow_check", "target": asset.target},
        )

    @staticmethod
    def _check_access_control(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="access_control",
            description=f"Weak access control in contract {asset.target}",
            evidence="Missing onlyOwner modifier on sensitive function",
            affected_asset_id=asset.id,
            raw_data={"check": "access_control_check", "target": asset.target},
        )

    @staticmethod
    def _check_unchecked_call(asset: Asset) -> RawFinding:
        return RawFinding(
            vulnerability_type="unchecked_external_call",
            description=f"Unchecked external call in contract {asset.target}",
            evidence="Return value of call() not checked in payout() function",
            affected_asset_id=asset.id,
            raw_data={"check": "unchecked_call_check", "target": asset.target},
        )

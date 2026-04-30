"""Реальный плагин сканирования смарт-контрактов.

Интегрирует slither и mythril через ProcessManager.
Парсит вывод через OutputParser. Пропускает недоступные инструменты.
"""

from __future__ import annotations

import logging

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig
from app.services.scan_plugins.base import ScanPlugin
from app.services.process_manager import ProcessManager
from app.services.output_parser import OutputParser
from app.services.tool_manager import ToolManager
from app.models.tool_schemas import ToolStatus

logger = logging.getLogger(__name__)


class RealContractPlugin(ScanPlugin):
    """Реальный плагин анализа смарт-контрактов: slither → mythril."""

    CHECK_NAMES = [
        "slither_static_analysis",
        "mythril_symbolic_execution",
    ]

    def __init__(
        self,
        process_manager: ProcessManager | None = None,
        output_parser: OutputParser | None = None,
        tool_manager: ToolManager | None = None,
    ) -> None:
        self._process_manager = process_manager or ProcessManager()
        self._output_parser = output_parser or OutputParser()
        self._tool_manager = tool_manager or ToolManager()

    def get_asset_type(self) -> AssetType:
        return AssetType.SMART_CONTRACT

    def get_check_names(self) -> list[str]:
        return list(self.CHECK_NAMES)

    def scan(self, asset: Asset, config: ScanConfig) -> list[RawFinding]:
        """Запускает slither → mythril. Пропускает недоступные."""
        all_findings: list[RawFinding] = []
        target = asset.target

        # slither
        if self._is_tool_available("slither"):
            findings = self._run_slither(target, asset.id)
            all_findings.extend(findings)
        else:
            logger.warning("slither not available, skipping static analysis")

        # mythril
        if self._is_tool_available("mythril"):
            findings = self._run_mythril(target, asset.id)
            all_findings.extend(findings)
        else:
            logger.warning("mythril not available, skipping symbolic execution")

        return all_findings

    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is installed and available."""
        try:
            info = self._tool_manager.discover_tool(tool_name)
            return info.status == ToolStatus.INSTALLED
        except Exception:
            return False

    def _run_slither(self, target: str, asset_id: str) -> list[RawFinding]:
        """Run slither with JSON output."""
        command = ["slither", target, "--json", "-"]
        result = self._process_manager.execute(command, timeout_seconds=600)

        if result.exit_code != 0 and not result.stdout.strip():
            logger.error(
                "slither failed (exit=%d): %s",
                result.exit_code,
                result.stderr[:500],
            )
            return []

        return self._output_parser.parse("slither", result.stdout, asset_id)

    def _run_mythril(self, target: str, asset_id: str) -> list[RawFinding]:
        """Run mythril with JSON output."""
        command = ["myth", "analyze", target, "-o", "json"]
        result = self._process_manager.execute(command, timeout_seconds=900)

        if result.exit_code != 0 and not result.stdout.strip():
            logger.error(
                "mythril failed (exit=%d): %s",
                result.exit_code,
                result.stderr[:500],
            )
            return []

        return self._output_parser.parse("mythril", result.stdout, asset_id)

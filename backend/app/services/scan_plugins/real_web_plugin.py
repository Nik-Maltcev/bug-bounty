"""Реальный плагин сканирования веб-приложений.

Интегрирует 14 инструментов через ProcessManager:
- Разведка: subfinder, amass, httpx, gau
- Перебор: gobuster, ffuf
- XSS: dalfox
- WAF/Технологии: wafw00f, whatweb, wpscan
- Уязвимости: nmap, nuclei, nikto, sqlmap

Парсит вывод через OutputParser. Пропускает недоступные инструменты.
"""

from __future__ import annotations

import logging

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig
from app.services.scan_plugins.base import ScanPlugin
from app.services.process_manager import ProcessManager
from app.services.output_parser import OutputParser
from app.services.tool_manager import ToolManager, SUPPORTED_TOOLS
from app.models.tool_schemas import ToolStatus

logger = logging.getLogger(__name__)


class RealWebPlugin(ScanPlugin):
    """Реальный плагин веб-сканирования с 14 инструментами."""

    CHECK_NAMES = [
        "subfinder_enum",
        "amass_enum",
        "httpx_probe",
        "gobuster_dir",
        "ffuf_fuzz",
        "gau_urls",
        "wafw00f_detect",
        "whatweb_fingerprint",
        "wpscan_wordpress",
        "nmap_port_scan",
        "nuclei_vuln_scan",
        "dalfox_xss_scan",
        "sqlmap_injection",
        "nikto_config_check",
    ]

    _TOOL_CHECK_MAP = {
        "subfinder": "subfinder_enum",
        "amass": "amass_enum",
        "httpx": "httpx_probe",
        "gobuster": "gobuster_dir",
        "ffuf": "ffuf_fuzz",
        "gau": "gau_urls",
        "wafw00f": "wafw00f_detect",
        "whatweb": "whatweb_fingerprint",
        "wpscan": "wpscan_wordpress",
        "nmap": "nmap_port_scan",
        "nuclei": "nuclei_vuln_scan",
        "dalfox": "dalfox_xss_scan",
        "sqlmap": "sqlmap_injection",
        "nikto": "nikto_config_check",
    }

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
        return AssetType.WEB_APPLICATION

    def get_check_names(self) -> list[str]:
        return list(self.CHECK_NAMES)

    def scan(self, asset: Asset, config: ScanConfig) -> list[RawFinding]:
        """Запускает все доступные инструменты поэтапно."""
        all_findings: list[RawFinding] = []
        target = asset.target

        # --- Разведка ---
        if self._is_tool_available("subfinder"):
            all_findings.extend(self._run_subfinder(target, asset.id))
        if self._is_tool_available("amass"):
            all_findings.extend(self._run_amass(target, asset.id))
        if self._is_tool_available("httpx"):
            all_findings.extend(self._run_httpx(target, asset.id))
        if self._is_tool_available("gau"):
            all_findings.extend(self._run_gau(target, asset.id))

        # --- Перебор ---
        if self._is_tool_available("gobuster"):
            all_findings.extend(self._run_gobuster(target, asset.id))
        if self._is_tool_available("ffuf"):
            all_findings.extend(self._run_ffuf(target, asset.id))

        # --- WAF / Технологии ---
        if self._is_tool_available("wafw00f"):
            all_findings.extend(self._run_wafw00f(target, asset.id))
        if self._is_tool_available("whatweb"):
            all_findings.extend(self._run_whatweb(target, asset.id))
        if self._is_tool_available("wpscan"):
            all_findings.extend(self._run_wpscan(target, asset.id))

        # --- Уязвимости ---
        if self._is_tool_available("nmap"):
            all_findings.extend(self._run_nmap(target, asset.id))
        if self._is_tool_available("nuclei"):
            all_findings.extend(self._run_nuclei(target, asset.id))
        if self._is_tool_available("dalfox"):
            all_findings.extend(self._run_dalfox(target, asset.id))
        if self._is_tool_available("sqlmap"):
            all_findings.extend(self._run_sqlmap(target, asset.id))
        if self._is_tool_available("nikto"):
            all_findings.extend(self._run_nikto(target, asset.id))

        return all_findings

    def _is_tool_available(self, tool_name: str) -> bool:
        try:
            info = self._tool_manager.discover_tool(tool_name)
            return info.status == ToolStatus.INSTALLED
        except Exception:
            return False

    # ------------------------------------------------------------------
    # subfinder
    # ------------------------------------------------------------------
    def _run_subfinder(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["subfinder", "-d", target, "-json"]
        result = self._process_manager.execute(command, timeout_seconds=300)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("subfinder failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("subfinder", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # amass
    # ------------------------------------------------------------------
    def _run_amass(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["amass", "enum", "-d", target, "-json", "-o", "-"]
        result = self._process_manager.execute(command, timeout_seconds=1800)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("amass failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("amass", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # httpx
    # ------------------------------------------------------------------
    def _run_httpx(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["httpx", "-u", target, "-json", "-title", "-tech-detect", "-status-code"]
        result = self._process_manager.execute(command, timeout_seconds=120)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("httpx failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("httpx", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # gobuster
    # ------------------------------------------------------------------
    def _run_gobuster(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["gobuster", "dir", "-u", target, "-w", "/usr/share/wordlists/common.txt", "-q"]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("gobuster failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("gobuster", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # ffuf
    # ------------------------------------------------------------------
    def _run_ffuf(self, target: str, asset_id: str) -> list[RawFinding]:
        command = [
            "ffuf", "-u", f"{target}/FUZZ",
            "-w", "/usr/share/wordlists/common.txt",
            "-json", "-mc", "200,204,301,302,307,401,403,405,500",
        ]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("ffuf failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("ffuf", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # gau
    # ------------------------------------------------------------------
    def _run_gau(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["gau", target]
        result = self._process_manager.execute(command, timeout_seconds=300)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("gau failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("gau", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # dalfox
    # ------------------------------------------------------------------
    def _run_dalfox(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["dalfox", "url", target, "-json"]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("dalfox failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("dalfox", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # wafw00f
    # ------------------------------------------------------------------
    def _run_wafw00f(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["wafw00f", target]
        result = self._process_manager.execute(command, timeout_seconds=120)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("wafw00f failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("wafw00f", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # whatweb
    # ------------------------------------------------------------------
    def _run_whatweb(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["whatweb", target, "--log-json", "-", "-q"]
        result = self._process_manager.execute(command, timeout_seconds=120)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("whatweb failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("whatweb", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # wpscan
    # ------------------------------------------------------------------
    def _run_wpscan(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["wpscan", "--url", target, "--format", "json", "--no-banner"]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("wpscan failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("wpscan", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # nmap
    # ------------------------------------------------------------------
    def _run_nmap(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["nmap", "-sV", "-T3", "--open", "-oX", "-", target]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("nmap failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("nmap", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # nuclei
    # ------------------------------------------------------------------
    def _run_nuclei(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["nuclei", "-u", target, "-silent", "-jsonl"]
        result = self._process_manager.execute(command, timeout_seconds=900)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("nuclei failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("nuclei", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # sqlmap
    # ------------------------------------------------------------------
    def _run_sqlmap(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["sqlmap", "-u", target, "--batch", "--risk=1", "--level=1"]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("sqlmap failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("sqlmap", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # nikto
    # ------------------------------------------------------------------
    def _run_nikto(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["nikto", "-h", target, "-Format", "json"]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("nikto failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("nikto", result.stdout, asset_id)

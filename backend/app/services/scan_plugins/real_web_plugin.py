"""Реальный плагин сканирования веб-приложений.

Интегрирует 24 инструмента через ProcessManager:
- Разведка: subfinder, amass, httpx, gau, assetfinder, katana
- Перебор: gobuster, ffuf, arjun, paramspider
- XSS: dalfox
- WAF/Технологии: wafw00f, whatweb, wpscan
- Уязвимости: nmap, nuclei, nikto, sqlmap
- Секреты: trufflehog, gitleaks
- SSL/TLS: testssl
- CORS: corsy
- DNS: dnsx

Парсит вывод через OutputParser. Пропускает недоступные инструменты.
"""

from __future__ import annotations

import logging
import re

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig
from app.services.scan_plugins.base import ScanPlugin, ProgressCallback
from app.services.process_manager import ProcessManager
from app.services.output_parser import OutputParser
from app.services.tool_manager import ToolManager, SUPPORTED_TOOLS
from app.models.tool_schemas import ToolStatus

logger = logging.getLogger(__name__)

# Human-readable tool names for progress display
TOOL_DISPLAY_NAMES = {
    "subfinder": "Поиск поддоменов (subfinder)",
    "assetfinder": "Поиск поддоменов (assetfinder)",
    "amass": "OSINT разведка (amass)",
    "httpx": "HTTP проверка (httpx)",
    "dnsx": "DNS анализ (dnsx)",
    "gau": "Исторические URL (gau)",
    "katana": "Краулинг сайта (katana)",
    "paramspider": "Поиск параметров (paramspider)",
    "gobuster": "Перебор директорий (gobuster)",
    "ffuf": "Фаззинг (ffuf)",
    "arjun": "Скрытые параметры (arjun)",
    "wafw00f": "Детект WAF (wafw00f)",
    "whatweb": "Технологии (whatweb)",
    "wpscan": "WordPress сканер (wpscan)",
    "testssl": "SSL/TLS анализ (testssl)",
    "corsy": "CORS проверка (corsy)",
    "nmap": "Сканирование портов (nmap)",
    "nuclei": "Поиск уязвимостей (nuclei)",
    "dalfox": "XSS сканер (dalfox)",
    "sqlmap": "SQL инъекции (sqlmap)",
    "nikto": "Веб-сканер (nikto)",
    "trufflehog": "Поиск секретов (trufflehog)",
    "gitleaks": "Git секреты (gitleaks)",
}


class RealWebPlugin(ScanPlugin):
    """Реальный плагин веб-сканирования с 24 инструментами."""

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
        # New checks
        "assetfinder_enum",
        "katana_crawl",
        "dnsx_dns",
        "testssl_scan",
        "arjun_params",
        "paramspider_params",
        "trufflehog_secrets",
        "gitleaks_secrets",
        "corsy_cors",
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
        # New mappings
        "assetfinder": "assetfinder_enum",
        "katana": "katana_crawl",
        "dnsx": "dnsx_dns",
        "testssl": "testssl_scan",
        "arjun": "arjun_params",
        "paramspider": "paramspider_params",
        "trufflehog": "trufflehog_secrets",
        "gitleaks": "gitleaks_secrets",
        "corsy": "corsy_cors",
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

    def scan(
        self, 
        asset: Asset, 
        config: ScanConfig,
        progress_callback: ProgressCallback | None = None,
    ) -> list[RawFinding]:
        """Запускает все доступные инструменты поэтапно."""
        all_findings: list[RawFinding] = []
        target = asset.target
        
        logger.info("Starting scan for target: %s", target)
        
        # Extract domain from target URL
        domain = self._extract_domain(target)
        
        # Build list of available tools in order
        tool_order = [
            ("subfinder", lambda: self._run_subfinder(domain, asset.id)),
            ("assetfinder", lambda: self._run_assetfinder(domain, asset.id)),
            ("amass", lambda: self._run_amass(domain, asset.id)),
            ("httpx", lambda: self._run_httpx(target, asset.id)),
            ("dnsx", lambda: self._run_dnsx(domain, asset.id)),
            ("gau", lambda: self._run_gau(domain, asset.id)),
            ("katana", lambda: self._run_katana(target, asset.id)),
            ("paramspider", lambda: self._run_paramspider(domain, asset.id)),
            ("gobuster", lambda: self._run_gobuster(target, asset.id)),
            ("ffuf", lambda: self._run_ffuf(target, asset.id)),
            ("arjun", lambda: self._run_arjun(target, asset.id)),
            ("wafw00f", lambda: self._run_wafw00f(target, asset.id)),
            ("whatweb", lambda: self._run_whatweb(target, asset.id)),
            ("wpscan", lambda: self._run_wpscan(target, asset.id)),
            ("testssl", lambda: self._run_testssl(target, asset.id)),
            ("corsy", lambda: self._run_corsy(target, asset.id)),
            ("nmap", lambda: self._run_nmap(target, asset.id)),
            ("nuclei", lambda: self._run_nuclei(target, asset.id)),
            ("dalfox", lambda: self._run_dalfox(target, asset.id)),
            ("sqlmap", lambda: self._run_sqlmap(target, asset.id)),
            ("nikto", lambda: self._run_nikto(target, asset.id)),
            ("trufflehog", lambda: self._run_trufflehog(target, asset.id)),
            ("gitleaks", lambda: self._run_gitleaks(target, asset.id)),
        ]
        
        # Filter to available tools only
        available_tools = [(name, func) for name, func in tool_order if self._is_tool_available(name)]
        total_tools = len(available_tools)
        
        logger.info("Available tools (%d): %s", total_tools, ", ".join(t[0] for t in available_tools))
        
        # Run each tool with progress updates
        for idx, (tool_name, run_func) in enumerate(available_tools):
            display_name = TOOL_DISPLAY_NAMES.get(tool_name, tool_name)
            
            # Update progress
            if progress_callback:
                progress_callback(display_name, idx, total_tools)
            
            logger.info("Running %s (%d/%d)...", tool_name, idx + 1, total_tools)
            
            try:
                findings = run_func()
                all_findings.extend(findings)
                logger.info("%s completed: %d findings", tool_name, len(findings))
            except Exception as e:
                logger.error("%s failed: %s", tool_name, str(e))
        
        # Final progress update
        if progress_callback:
            progress_callback("Завершение", total_tools, total_tools)
        
        logger.info("Scan completed. Total findings: %d", len(all_findings))
        return all_findings

    def _extract_domain(self, target: str) -> str:
        """Извлекает домен из URL."""
        # Remove protocol
        domain = re.sub(r'^https?://', '', target)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        return domain

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
    # httpx (using httpx-pd binary to avoid Python httpx conflict)
    # ------------------------------------------------------------------
    def _run_httpx(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["httpx-pd", "-u", target, "-json", "-title", "-tech-detect", "-status-code"]
        result = self._process_manager.execute(command, timeout_seconds=120)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("httpx-pd failed (exit=%d)", result.exit_code)
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

    # ==================================================================
    # NEW DEEP SCANNING TOOLS
    # ==================================================================

    # ------------------------------------------------------------------
    # assetfinder - subdomain discovery
    # ------------------------------------------------------------------
    def _run_assetfinder(self, domain: str, asset_id: str) -> list[RawFinding]:
        command = ["assetfinder", "--subs-only", domain]
        result = self._process_manager.execute(command, timeout_seconds=300)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("assetfinder failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("assetfinder", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # katana - web crawler
    # ------------------------------------------------------------------
    def _run_katana(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["katana", "-u", target, "-json", "-silent", "-d", "3"]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("katana failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("katana", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # dnsx - DNS toolkit
    # ------------------------------------------------------------------
    def _run_dnsx(self, domain: str, asset_id: str) -> list[RawFinding]:
        command = ["dnsx", "-d", domain, "-json", "-silent", "-a", "-aaaa", "-cname", "-mx", "-txt"]
        result = self._process_manager.execute(command, timeout_seconds=120)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("dnsx failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("dnsx", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # testssl - SSL/TLS scanner
    # ------------------------------------------------------------------
    def _run_testssl(self, target: str, asset_id: str) -> list[RawFinding]:
        # Extract host from URL
        host = re.sub(r'^https?://', '', target).split('/')[0]
        command = ["testssl", "--jsonfile", "-", "--quiet", host]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("testssl failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("testssl", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # arjun - hidden parameter discovery
    # ------------------------------------------------------------------
    def _run_arjun(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["arjun", "-u", target, "-oJ", "-", "-q"]
        result = self._process_manager.execute(command, timeout_seconds=600)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("arjun failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("arjun", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # paramspider - parameter mining from archives
    # ------------------------------------------------------------------
    def _run_paramspider(self, domain: str, asset_id: str) -> list[RawFinding]:
        command = ["paramspider", "-d", domain, "--quiet"]
        result = self._process_manager.execute(command, timeout_seconds=300)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("paramspider failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("paramspider", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # trufflehog - secret scanner
    # ------------------------------------------------------------------
    def _run_trufflehog(self, target: str, asset_id: str) -> list[RawFinding]:
        # Scan for secrets in web content
        command = ["trufflehog", "filesystem", "--json", "--no-update", target]
        result = self._process_manager.execute(command, timeout_seconds=300)
        # trufflehog returns 0 even with no findings
        if not result.stdout.strip():
            return []
        return self._output_parser.parse("trufflehog", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # gitleaks - git secret scanner
    # ------------------------------------------------------------------
    def _run_gitleaks(self, target: str, asset_id: str) -> list[RawFinding]:
        # Try to find exposed .git directories
        command = ["gitleaks", "detect", "--source", ".", "--report-format", "json", "--no-git"]
        result = self._process_manager.execute(command, timeout_seconds=300)
        if not result.stdout.strip():
            return []
        return self._output_parser.parse("gitleaks", result.stdout, asset_id)

    # ------------------------------------------------------------------
    # corsy - CORS misconfiguration scanner
    # ------------------------------------------------------------------
    def _run_corsy(self, target: str, asset_id: str) -> list[RawFinding]:
        command = ["corsy", "-u", target, "-o", "json"]
        result = self._process_manager.execute(command, timeout_seconds=120)
        if result.exit_code != 0 and not result.stdout.strip():
            logger.error("corsy failed (exit=%d)", result.exit_code)
            return []
        return self._output_parser.parse("corsy", result.stdout, asset_id)

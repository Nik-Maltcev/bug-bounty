"""Менеджер инструментов безопасности — обнаружение, установка, управление версиями.

Отвечает за проверку наличия инструментов в PATH, определение версий,
установку через пакетные менеджеры и фильтрацию по типу актива.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from app.core.tool_exceptions import ToolInstallError, ToolNotFoundError
from app.models.schemas import AssetType
from app.models.tool_schemas import ToolInfo, ToolSpec, ToolStatus

logger = logging.getLogger(__name__)


def _compare_versions(current: str, required: str) -> bool:
    """Сравнивает две semver-строки: возвращает True если current >= required.

    Поддерживает формат major.minor.patch (недостающие компоненты = 0).
    """

    def _parse(v: str) -> tuple[int, ...]:
        parts = re.split(r"[.\-+]", v.strip())
        nums: list[int] = []
        for p in parts:
            try:
                nums.append(int(p))
            except ValueError:
                break
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums[:3])

    return _parse(current) >= _parse(required)


# ---------------------------------------------------------------------------
# Реестр поддерживаемых инструментов
# ---------------------------------------------------------------------------

SUPPORTED_TOOLS: dict[str, ToolSpec] = {
    "nmap": ToolSpec(
        name="nmap",
        binary_name="nmap",
        min_version="7.80",
        version_command=["nmap", "--version"],
        version_regex=r"Nmap version ([\d.]+)",
        install_commands={
            "apt": ["sudo", "apt-get", "install", "-y", "nmap"],
            "brew": ["brew", "install", "nmap"],
            "choco": ["choco", "install", "nmap", "-y"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["-sV", "-T3", "--open"],
        output_format="xml",
    ),
    "nuclei": ToolSpec(
        name="nuclei",
        binary_name="nuclei",
        min_version="2.9.0",
        version_command=["nuclei", "-version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "go": ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["-silent", "-severity", "low,medium,high,critical"],
        output_format="json",
    ),
    "nikto": ToolSpec(
        name="nikto",
        binary_name="nikto",
        min_version="2.1.6",
        version_command=["nikto", "-Version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "apt": ["sudo", "apt-get", "install", "-y", "nikto"],
            "brew": ["brew", "install", "nikto"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["-Format", "json", "-Tuning", "1"],
        output_format="json",
    ),
    "sqlmap": ToolSpec(
        name="sqlmap",
        binary_name="sqlmap",
        min_version="1.7",
        version_command=["sqlmap", "--version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "pip": ["pip", "install", "sqlmap"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["--batch", "--risk=1", "--level=1"],
        output_format="text",
    ),
    # --- Новые инструменты ---
    "subfinder": ToolSpec(
        name="subfinder",
        binary_name="subfinder",
        min_version="2.6.0",
        version_command=["subfinder", "-version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "go": ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["-json"],
        output_format="json",
    ),
    "amass": ToolSpec(
        name="amass",
        binary_name="amass",
        min_version="3.23.0",
        version_command=["amass", "-version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "go": ["go", "install", "-v", "github.com/OWASP/Amass/v3/...@master"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["enum", "-json"],
        output_format="json",
    ),
    "httpx": ToolSpec(
        name="httpx",
        binary_name="httpx-pd",  # Renamed to avoid conflict with Python httpx
        min_version="1.3.0",
        version_command=["httpx-pd", "-version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "go": ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["-json", "-title", "-tech-detect", "-status-code"],
        output_format="json",
    ),
    "gobuster": ToolSpec(
        name="gobuster",
        binary_name="gobuster",
        min_version="3.6.0",
        version_command=["gobuster", "--help"],  # gobuster doesn't have version command
        version_regex=r"gobuster",  # Just check if it runs
        install_commands={
            "go": ["go", "install", "-v", "github.com/OJ/gobuster/v3@latest"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["dir", "-q"],
        output_format="text",
    ),
    "ffuf": ToolSpec(
        name="ffuf",
        binary_name="ffuf",
        min_version="2.1.0",
        version_command=["ffuf", "-V"],
        version_regex=r"([\d.]+)",
        install_commands={
            "go": ["go", "install", "-v", "github.com/ffuf/ffuf/v2@latest"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["-json", "-mc", "200,204,301,302,307,401,403,405,500"],
        output_format="json",
    ),
    "gau": ToolSpec(
        name="gau",
        binary_name="gau",
        min_version="2.1.0",
        version_command=["gau", "--version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "go": ["go", "install", "-v", "github.com/lc/gau/v2/cmd/gau@latest"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=[],
        output_format="text",
    ),
    "dalfox": ToolSpec(
        name="dalfox",
        binary_name="dalfox",
        min_version="2.9.0",
        version_command=["dalfox", "version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "go": ["go", "install", "-v", "github.com/hahwul/dalfox/v2@latest"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["-json"],
        output_format="json",
    ),
    "wafw00f": ToolSpec(
        name="wafw00f",
        binary_name="wafw00f",
        min_version="2.2.0",
        version_command=["wafw00f", "--version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "pip": ["pip", "install", "wafw00f"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=[],
        output_format="text",
    ),
    "wpscan": ToolSpec(
        name="wpscan",
        binary_name="wpscan",
        min_version="3.8.0",
        version_command=["wpscan", "--version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "gem": ["gem", "install", "wpscan"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["--format", "json", "--no-banner"],
        output_format="json",
    ),
    "whatweb": ToolSpec(
        name="whatweb",
        binary_name="whatweb",
        min_version="0.5.0",
        version_command=["whatweb", "--version"],
        version_regex=r"([\d.]+)",
        install_commands={
            "gem": ["gem", "install", "whatweb"],
        },
        asset_types=[AssetType.WEB_APPLICATION],
        default_args=["--log-json", "-q"],
        output_format="json",
    ),
}


class ToolManager:
    """Менеджер обнаружения и управления инструментами безопасности."""

    def __init__(self) -> None:
        self._specs = SUPPORTED_TOOLS

    # ------------------------------------------------------------------
    # Публичные методы
    # ------------------------------------------------------------------

    def discover_all(self) -> list[ToolInfo]:
        """Обнаруживает все поддерживаемые инструменты в системе."""
        results: list[ToolInfo] = []
        for tool_name in self._specs:
            results.append(self.discover_tool(tool_name))
        return results

    def discover_tool(self, tool_name: str) -> ToolInfo:
        """Обнаруживает конкретный инструмент."""
        if tool_name not in self._specs:
            raise ToolNotFoundError(tool_name, f"Инструмент '{tool_name}' не поддерживается")

        spec = self._specs[tool_name]
        path = shutil.which(spec.binary_name)

        if path is None:
            logger.info("Tool %s not found in PATH", tool_name)
            return ToolInfo(
                name=spec.name,
                status=ToolStatus.NOT_INSTALLED,
                version=None,
                min_version=spec.min_version,
                path=None,
                install_command=self._get_install_command(spec),
                asset_types=spec.asset_types,
            )

        version = self._detect_version(spec)
        if version and _compare_versions(version, spec.min_version):
            status = ToolStatus.INSTALLED
        elif version:
            status = ToolStatus.OUTDATED
        else:
            # Found in PATH but couldn't determine version — treat as installed
            status = ToolStatus.INSTALLED

        return ToolInfo(
            name=spec.name,
            status=status,
            version=version,
            min_version=spec.min_version,
            path=path,
            install_command=self._get_install_command(spec),
            asset_types=spec.asset_types,
        )

    def install_tool(self, tool_name: str) -> ToolInfo:
        """Устанавливает инструмент через пакетный менеджер."""
        if tool_name not in self._specs:
            raise ToolNotFoundError(tool_name, f"Инструмент '{tool_name}' не поддерживается")

        spec = self._specs[tool_name]
        install_cmd = self._pick_install_command(spec)

        logger.info("Installing %s via: %s", tool_name, " ".join(install_cmd))
        try:
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                raise ToolInstallError(
                    tool_name,
                    reason=result.stderr or "non-zero exit code",
                    manual_instructions=self._get_install_command(spec),
                )
        except FileNotFoundError:
            raise ToolInstallError(
                tool_name,
                reason="Package manager not found",
                manual_instructions=self._get_install_command(spec),
            )
        except subprocess.TimeoutExpired:
            raise ToolInstallError(
                tool_name,
                reason="Installation timed out",
                manual_instructions=self._get_install_command(spec),
            )

        return self.discover_tool(tool_name)

    def get_tools_for_asset_type(self, asset_type: AssetType) -> list[ToolInfo]:
        """Возвращает инструменты, применимые к типу актива."""
        results: list[ToolInfo] = []
        for tool_name, spec in self._specs.items():
            if asset_type in spec.asset_types:
                results.append(self.discover_tool(tool_name))
        return results

    def check_version(self, tool_name: str) -> bool:
        """Проверяет соответствие версии минимальной поддерживаемой."""
        info = self.discover_tool(tool_name)
        return info.status == ToolStatus.INSTALLED

    # ------------------------------------------------------------------
    # Приватные методы
    # ------------------------------------------------------------------

    def _detect_version(self, spec: ToolSpec) -> str | None:
        """Определяет версию инструмента через subprocess."""
        try:
            result = subprocess.run(
                spec.version_command,
                capture_output=True,
                text=True,
                timeout=15,
            )
            combined = result.stdout + result.stderr
            match = re.search(spec.version_regex, combined)
            if match:
                return match.group(1)
        except Exception:
            logger.debug("Failed to detect version for %s", spec.name)
        return None

    @staticmethod
    def _get_install_command(spec: ToolSpec) -> str:
        """Возвращает строку команды установки (первый доступный менеджер)."""
        for _mgr, cmd in spec.install_commands.items():
            return " ".join(cmd)
        return f"Install {spec.name} manually"

    @staticmethod
    def _pick_install_command(spec: ToolSpec) -> list[str]:
        """Выбирает первую доступную команду установки."""
        for _mgr, cmd in spec.install_commands.items():
            return cmd
        return []

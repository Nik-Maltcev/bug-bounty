"""Реальный плагин сканирования API-эндпоинтов.

Интегрирует OWASP ZAP (пассивное сканирование) и пользовательский фаззинг.
Ограничивает фаззинг эндпоинтами в scope.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig
from app.services.scan_plugins.base import ScanPlugin
from app.services.process_manager import ProcessManager
from app.services.output_parser import OutputParser
from app.services.tool_manager import ToolManager
from app.models.tool_schemas import ToolStatus

logger = logging.getLogger(__name__)


class RealApiPlugin(ScanPlugin):
    """Реальный плагин API-сканирования: OWASP ZAP + фаззинг."""

    CHECK_NAMES = [
        "zap_passive_scan",
        "api_fuzzing",
    ]

    def __init__(
        self,
        process_manager: ProcessManager | None = None,
        output_parser: OutputParser | None = None,
        tool_manager: ToolManager | None = None,
        allowed_endpoints: list[str] | None = None,
    ) -> None:
        self._process_manager = process_manager or ProcessManager()
        self._output_parser = output_parser or OutputParser()
        self._tool_manager = tool_manager or ToolManager()
        self._allowed_endpoints: list[str] = allowed_endpoints or []

    def get_asset_type(self) -> AssetType:
        return AssetType.API

    def get_check_names(self) -> list[str]:
        return list(self.CHECK_NAMES)

    def scan(self, asset: Asset, config: ScanConfig) -> list[RawFinding]:
        """Запускает ZAP пассивное сканирование → фаззинг."""
        all_findings: list[RawFinding] = []
        target = asset.target

        # ZAP passive scan
        if self._is_tool_available("zap"):
            findings = self._run_zap_passive(target, asset.id)
            all_findings.extend(findings)
        else:
            logger.warning("OWASP ZAP not available, skipping passive scan")

        # Custom API fuzzing — limited to in-scope endpoints
        findings = self._run_api_fuzzing(target, asset, config)
        all_findings.extend(findings)

        return all_findings

    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is installed and available."""
        try:
            info = self._tool_manager.discover_tool(tool_name)
            return info.status == ToolStatus.INSTALLED
        except Exception:
            return False

    def _run_zap_passive(self, target: str, asset_id: str) -> list[RawFinding]:
        """Run OWASP ZAP in passive scan mode."""
        command = [
            "zap-cli", "quick-scan", "--self-contained",
            "--spider", "-r", target,
        ]
        result = self._process_manager.execute(command, timeout_seconds=600)

        if result.exit_code != 0 and not result.stdout.strip():
            logger.error(
                "ZAP failed (exit=%d): %s",
                result.exit_code,
                result.stderr[:500],
            )
            return []

        return self._output_parser.parse("zap", result.stdout, asset_id)

    def _run_api_fuzzing(
        self, target: str, asset: Asset, config: ScanConfig
    ) -> list[RawFinding]:
        """Run custom API fuzzing, limited to in-scope endpoints."""
        findings: list[RawFinding] = []

        # Determine in-scope endpoints
        in_scope = self._get_in_scope_endpoints(target, asset)
        if not in_scope:
            logger.info("No in-scope endpoints for fuzzing, skipping")
            return findings

        for endpoint in in_scope:
            endpoint_findings = self._fuzz_endpoint(endpoint, asset.id)
            findings.extend(endpoint_findings)

        return findings

    def _get_in_scope_endpoints(self, target: str, asset: Asset) -> list[str]:
        """Return only endpoints that are within the asset's scope."""
        # Use explicitly allowed endpoints if provided
        if self._allowed_endpoints:
            return [
                ep for ep in self._allowed_endpoints
                if self._is_endpoint_in_scope(ep, target)
            ]

        # Default: the target itself is in scope if asset is in_scope
        if asset.in_scope:
            return [target]
        return []

    @staticmethod
    def _is_endpoint_in_scope(endpoint: str, target: str) -> bool:
        """Check if an endpoint belongs to the target's domain."""
        try:
            ep_parsed = urlparse(endpoint)
            target_parsed = urlparse(target)
            ep_host = ep_parsed.hostname or ""
            target_host = target_parsed.hostname or target
            return ep_host == target_host or endpoint.startswith(target)
        except Exception:
            return False

    def _fuzz_endpoint(self, endpoint: str, asset_id: str) -> list[RawFinding]:
        """Fuzz a single endpoint with boundary/invalid inputs."""
        findings: list[RawFinding] = []

        # Simple fuzzing payloads for common API issues
        fuzz_payloads = [
            ("", "empty_input"),
            ("' OR 1=1 --", "sql_injection"),
            ("<script>alert(1)</script>", "xss"),
            ("A" * 10000, "buffer_overflow"),
            ("{{7*7}}", "template_injection"),
            ("../../../etc/passwd", "path_traversal"),
        ]

        for payload, vuln_type in fuzz_payloads:
            # Use curl-like approach via process manager
            command = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps({"input": payload}),
                endpoint,
            ]

            try:
                result = self._process_manager.execute(
                    command, timeout_seconds=30
                )
                status_code = result.stdout.strip()

                # Flag 500 errors as potential vulnerabilities
                if status_code == "500":
                    findings.append(RawFinding(
                        vulnerability_type=f"api_fuzzing_{vuln_type}",
                        description=f"Server error (500) with {vuln_type} payload at {endpoint}",
                        evidence=f"Payload: {payload[:100]}, Status: {status_code}",
                        affected_asset_id=asset_id,
                        raw_data={
                            "tool": "api_fuzzer",
                            "endpoint": endpoint,
                            "payload_type": vuln_type,
                            "status_code": status_code,
                        },
                    ))
            except Exception:
                logger.debug("Fuzzing request failed for %s", endpoint)

        return findings

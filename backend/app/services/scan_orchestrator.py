"""Оркестратор сканирования — выбор инструментов, порядок запуска, координация.

Интеллектуальный выбор и упорядочивание инструментов на основе типа актива,
правил программы и доступности.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict

from app.core.tool_exceptions import NoToolsAvailableError
from app.models.schemas import (
    Asset,
    AssetType,
    ProgramRule,
    RawFinding,
    ScanConfig,
)
from app.models.tool_schemas import ExcludedTool, ScanPlan, ToolStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Зависимости между инструментами
# ---------------------------------------------------------------------------

TOOL_DEPENDENCIES: dict[str, list[str]] = {
    "httpx": ["subfinder", "amass"],
    "gobuster": ["httpx"],
    "ffuf": ["httpx"],
    "nuclei": ["httpx"],
    "dalfox": ["ffuf", "gobuster"],
    "sqlmap": ["ffuf", "gobuster"],
    "nikto": ["httpx"],
    "wpscan": ["whatweb"],
}

# ---------------------------------------------------------------------------
# Маппинг типов активов на инструменты
# ---------------------------------------------------------------------------

ASSET_TOOL_MAP: dict[AssetType, list[str]] = {
    AssetType.WEB_APPLICATION: [
        "subfinder", "amass", "httpx", "gobuster", "ffuf", "gau",
        "wafw00f", "whatweb", "wpscan",
        "nmap", "nuclei", "dalfox", "sqlmap", "nikto",
    ],
}


class ScanOrchestrator:
    """Оркестратор: выбор инструментов, порядок запуска, координация."""

    def __init__(
        self,
        tool_manager=None,
        safety_layer=None,
    ) -> None:
        self._tool_manager = tool_manager
        self._safety_layer = safety_layer

    # ------------------------------------------------------------------
    # Публичные методы
    # ------------------------------------------------------------------

    def create_scan_plan(
        self,
        asset: Asset,
        rules: list[ProgramRule] | None = None,
    ) -> ScanPlan:
        """Формирует план сканирования.

        1. Определяет применимые инструменты по типу актива
        2. Фильтрует по правилам программы
        3. Проверяет доступность через ToolManager
        4. Определяет порядок с учётом зависимостей
        """
        rules = rules or []
        scan_id = uuid.uuid4().hex[:12]

        # 1. Инструменты для данного типа актива
        candidate_tools = list(ASSET_TOOL_MAP.get(asset.asset_type, []))
        excluded: list[ExcludedTool] = []

        if not candidate_tools:
            raise NoToolsAvailableError(
                asset.asset_type,
                recommended_tools=["nmap", "nuclei"],
            )

        # 2. Фильтрация по правилам программы
        candidate_tools, rule_excluded = self._filter_by_rules(candidate_tools, rules)
        excluded.extend(rule_excluded)

        # 3. Проверка доступности через ToolManager
        if self._tool_manager is not None:
            available: list[str] = []
            for tool_name in candidate_tools:
                try:
                    info = self._tool_manager.discover_tool(tool_name)
                    if info.status == ToolStatus.INSTALLED:
                        available.append(tool_name)
                    else:
                        excluded.append(ExcludedTool(
                            tool_name=tool_name,
                            reason=f"not available (status: {info.status.value})",
                        ))
                except Exception:
                    excluded.append(ExcludedTool(
                        tool_name=tool_name,
                        reason="discovery error",
                    ))
            candidate_tools = available

        # 4. Топологическая сортировка
        execution_order = self._order_by_dependencies(candidate_tools)

        if not execution_order:
            all_tools = ASSET_TOOL_MAP.get(asset.asset_type, [])
            raise NoToolsAvailableError(
                asset.asset_type,
                recommended_tools=all_tools,
            )

        return ScanPlan(
            scan_id=scan_id,
            asset_type=asset.asset_type,
            target=asset.target,
            tools=candidate_tools,
            excluded_tools=excluded,
            execution_order=execution_order,
        )

    def execute_plan(
        self,
        plan: ScanPlan,
        asset: Asset,
        config: ScanConfig,
        plugins: dict | None = None,
    ) -> list[RawFinding]:
        """Выполняет план сканирования, собирает все находки."""
        all_findings: list[RawFinding] = []
        plugins = plugins or {}

        for tool_name in plan.execution_order:
            # Safety check
            if self._safety_layer is not None:
                if self._safety_layer.is_kill_switch_active():
                    logger.warning("Kill switch active, aborting scan plan")
                    break
                if not self._safety_layer.check_rate_limit(plan.target):
                    logger.warning("Rate limit exceeded for %s", plan.target)
                    continue

            plugin = plugins.get(tool_name)
            if plugin is not None:
                try:
                    findings = plugin.scan(asset, config)
                    all_findings.extend(findings)
                except Exception:
                    logger.exception("Plugin error for tool %s", tool_name)

        return all_findings

    # ------------------------------------------------------------------
    # Приватные методы
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_by_rules(
        tools: list[str], rules: list[ProgramRule]
    ) -> tuple[list[str], list[ExcludedTool]]:
        """Фильтрует инструменты по правилам программы.

        Правило блокирует инструмент, если:
        - rule.is_allowed is False
        - имя инструмента встречается в описании правила (case-insensitive)
        """
        blocked_keywords: dict[str, str] = {}
        for rule in rules:
            if not rule.is_allowed:
                desc_lower = rule.description.lower()
                for tool in tools:
                    if tool.lower() in desc_lower:
                        blocked_keywords[tool] = rule.description

        allowed: list[str] = []
        excluded: list[ExcludedTool] = []
        for tool in tools:
            if tool in blocked_keywords:
                excluded.append(ExcludedTool(
                    tool_name=tool,
                    reason=f"blocked by rule: {blocked_keywords[tool]}",
                ))
            else:
                allowed.append(tool)

        return allowed, excluded

    @staticmethod
    def _order_by_dependencies(tools: list[str]) -> list[str]:
        """Топологическая сортировка инструментов по зависимостям (Kahn's algorithm)."""
        tool_set = set(tools)

        # Build adjacency list and in-degree count for tools in the set
        graph: dict[str, list[str]] = defaultdict(list)
        in_degree: dict[str, int] = {t: 0 for t in tools}

        for tool in tools:
            deps = TOOL_DEPENDENCIES.get(tool, [])
            for dep in deps:
                if dep in tool_set:
                    graph[dep].append(tool)
                    in_degree[tool] += 1

        # Kahn's algorithm
        queue = [t for t in tools if in_degree[t] == 0]
        # Sort queue for deterministic output
        queue.sort()
        result: list[str] = []

        while queue:
            node = queue.pop(0)
            result.append(node)
            for neighbor in sorted(graph[node]):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
            queue.sort()

        return result

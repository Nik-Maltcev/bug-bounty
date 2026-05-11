"""Оркестратор сканирования — выбор инструментов, порядок запуска, координация.

Интеллектуальный выбор и упорядочивание инструментов на основе типа актива,
правил программы и доступности. Поддерживает двухэтапное сканирование:
Stage 1 (инструменты) и Stage 2 (AI-Driven Scan).
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from typing import TYPE_CHECKING

from app.core.tool_exceptions import NoToolsAvailableError
from app.models.schemas import (
    Asset,
    AssetType,
    ProgramRule,
    RawFinding,
    ScanConfig,
)
from app.models.tool_schemas import ExcludedTool, ScanPlan, ToolStatus

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from app.services.ai.ai_scanner import AIScanner
    from app.models.ai_scan_schemas import AIScanResult

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
    """Оркестратор: выбор инструментов, порядок запуска, координация.

    Поддерживает двухэтапное сканирование:
    - Stage 1: автоматическое сканирование инструментами (nmap, nuclei, nikto и др.)
    - Stage 2: AI-Driven Scan — DeepSeek анализирует результаты и генерирует целевые тесты
    """

    def __init__(
        self,
        tool_manager=None,
        safety_layer=None,
        ai_scanner: AIScanner | None = None,
        db: Session | None = None,
    ) -> None:
        self._tool_manager = tool_manager
        self._safety_layer = safety_layer
        self._ai_scanner = ai_scanner
        self._db = db

    # ------------------------------------------------------------------
    # Публичные методы
    # ------------------------------------------------------------------

    def create_scan_plan(
        self,
        asset: Asset,
        rules: list[ProgramRule] | None = None,
        enable_ai_stage2: bool = False,
        ai_supervised_mode: bool = False,
        ai_max_iterations: int = 3,
        ai_max_requests: int = 50,
        ai_rate_limit: float = 5.0,
    ) -> ScanPlan:
        """Формирует план сканирования.

        1. Определяет применимые инструменты по типу актива
        2. Фильтрует по правилам программы
        3. Проверяет доступность через ToolManager
        4. Определяет порядок с учётом зависимостей
        5. Настраивает Stage 2 (AI-Driven Scan) если включён

        Args:
            asset: актив для сканирования.
            rules: правила программы.
            enable_ai_stage2: включить AI-Driven Scan после Stage 1.
            ai_supervised_mode: режим одобрения для AI-запросов.
            ai_max_iterations: максимум итераций AI (1-5).
            ai_max_requests: максимум AI-запросов (10-200).
            ai_rate_limit: лимит запросов в секунду.
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
            enable_ai_stage2=enable_ai_stage2,
            ai_supervised_mode=ai_supervised_mode,
            ai_max_iterations=ai_max_iterations,
            ai_max_requests=ai_max_requests,
            ai_rate_limit=ai_rate_limit,
        )

    def execute_plan(
        self,
        plan: ScanPlan,
        asset: Asset,
        config: ScanConfig,
        plugins: dict | None = None,
        rules: list[ProgramRule] | None = None,
        scope: list[Asset] | None = None,
    ) -> list[RawFinding]:
        """Выполняет план сканирования, собирает все находки.

        Args:
            plan: план сканирования.
            asset: актив для сканирования.
            config: конфигурация сканирования.
            plugins: плагины инструментов.
            rules: правила программы (для Stage 2).
            scope: активы программы (для Stage 2).

        Returns:
            Список находок Stage 1.
        """
        all_findings: list[RawFinding] = []
        plugins = plugins or {}

        # === Stage 1: Инструменты ===
        logger.info("Stage 1 [%s]: Starting tool-based scan", plan.scan_id)

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

        logger.info(
            "Stage 1 [%s]: Completed with %d findings",
            plan.scan_id,
            len(all_findings),
        )

        # === Stage 2: AI-Driven Scan (если включён) ===
        if plan.enable_ai_stage2:
            self._execute_stage2(plan, asset, config, all_findings, rules, scope)

        return all_findings

    def _execute_stage2(
        self,
        plan: ScanPlan,
        asset: Asset,
        config: ScanConfig,
        stage1_findings: list[RawFinding],
        rules: list[ProgramRule] | None = None,
        scope: list[Asset] | None = None,
    ) -> AIScanResult | None:
        """Выполняет Stage 2 (AI-Driven Scan).

        Args:
            plan: план сканирования.
            asset: актив.
            config: конфигурация.
            stage1_findings: находки Stage 1.
            rules: правила программы.
            scope: активы программы.

        Returns:
            Результат AI-сканирования или None при ошибке.
        """
        if self._ai_scanner is None:
            logger.warning(
                "Stage 2 [%s]: AI Scanner not configured, skipping",
                plan.scan_id,
            )
            return None

        # Проверяем Kill Switch
        if self._safety_layer is not None and self._safety_layer.is_kill_switch_active():
            logger.warning("Stage 2 [%s]: Kill switch active, skipping", plan.scan_id)
            return None

        logger.info(
            "Stage 2 [%s]: Starting AI-Driven Scan (supervised=%s, max_iter=%d, max_req=%d)",
            plan.scan_id,
            plan.ai_supervised_mode,
            plan.ai_max_iterations,
            plan.ai_max_requests,
        )

        try:
            result = self._ai_scanner.run_stage2(
                scan_id=plan.scan_id,
                stage1_results=stage1_findings,
                target_url=plan.target,
                program_id=config.program_id,
                rules=rules,
                scope=scope,
                supervised_mode=plan.ai_supervised_mode,
                max_iterations=plan.ai_max_iterations,
                max_requests=plan.ai_max_requests,
                rate_limit=plan.ai_rate_limit,
            )

            logger.info(
                "Stage 2 [%s]: Completed with %d findings (status=%s)",
                plan.scan_id,
                len(result.findings),
                result.status,
            )

            return result

        except Exception as e:
            logger.exception("Stage 2 [%s]: Failed with error: %s", plan.scan_id, e)
            return None

    def execute_stage2_standalone(
        self,
        scan_id: str,
        stage1_findings: list[RawFinding],
        target_url: str,
        program_id: str,
        rules: list[ProgramRule] | None = None,
        scope: list[Asset] | None = None,
        supervised_mode: bool = False,
        max_iterations: int = 3,
        max_requests: int = 50,
        rate_limit: float = 5.0,
    ) -> AIScanResult | None:
        """Запускает Stage 2 отдельно от Stage 1.

        Используется для повторного AI-анализа существующих результатов.

        Args:
            scan_id: ID сканирования.
            stage1_findings: результаты Stage 1.
            target_url: URL цели.
            program_id: ID программы.
            rules: правила программы.
            scope: активы программы.
            supervised_mode: режим одобрения.
            max_iterations: максимум итераций.
            max_requests: максимум запросов.
            rate_limit: лимит запросов в секунду.

        Returns:
            Результат AI-сканирования или None.
        """
        if self._ai_scanner is None:
            logger.error("Stage 2 standalone: AI Scanner not configured")
            return None

        logger.info("Stage 2 standalone [%s]: Starting", scan_id)

        try:
            result = self._ai_scanner.run_stage2(
                scan_id=scan_id,
                stage1_results=stage1_findings,
                target_url=target_url,
                program_id=program_id,
                rules=rules,
                scope=scope,
                supervised_mode=supervised_mode,
                max_iterations=max_iterations,
                max_requests=max_requests,
                rate_limit=rate_limit,
            )

            logger.info(
                "Stage 2 standalone [%s]: Completed with %d findings",
                scan_id,
                len(result.findings),
            )

            return result

        except Exception as e:
            logger.exception("Stage 2 standalone [%s]: Failed: %s", scan_id, e)
            return None

    def stop_stage2(self) -> bool:
        """Останавливает Stage 2 (Kill Switch).

        Returns:
            True если остановка инициирована.
        """
        if self._ai_scanner is None:
            return False

        self._ai_scanner.stop()
        logger.warning("Stage 2: Kill switch activated")
        return True

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

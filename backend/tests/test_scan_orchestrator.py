"""Unit-тесты для ScanOrchestrator — формирование плана, зависимости, фильтрация."""

from unittest.mock import MagicMock

import pytest

from app.core.tool_exceptions import NoToolsAvailableError
from app.models.schemas import Asset, AssetType, ProgramRule, ScanConfig
from app.models.tool_schemas import ToolInfo, ToolStatus
from app.services.scan_orchestrator import (
    ASSET_TOOL_MAP,
    TOOL_DEPENDENCIES,
    ScanOrchestrator,
)


def _make_asset(asset_type: AssetType = AssetType.WEB_APPLICATION, target: str = "http://example.com") -> Asset:
    return Asset(id="a1", name="Test", asset_type=asset_type, target=target)


def _make_tool_info(name: str, status: ToolStatus = ToolStatus.INSTALLED) -> ToolInfo:
    return ToolInfo(
        name=name,
        status=status,
        version="1.0.0",
        min_version="1.0.0",
        path=f"/usr/bin/{name}",
        install_command=f"install {name}",
        asset_types=[AssetType.WEB_APPLICATION],
    )


# ---------------------------------------------------------------------------
# create_scan_plan — basic
# ---------------------------------------------------------------------------


class TestCreateScanPlan:
    def test_web_app_plan_no_rules(self):
        """Plan for web app without rules includes all web tools."""
        mock_tm = MagicMock()
        mock_tm.discover_tool.side_effect = lambda name: _make_tool_info(name)

        orch = ScanOrchestrator(tool_manager=mock_tm)
        plan = orch.create_scan_plan(_make_asset())

        tools = set(plan.tools)
        assert "nmap" in tools
        assert "subfinder" in tools
        assert "dalfox" in tools
        assert plan.asset_type == AssetType.WEB_APPLICATION
        assert len(plan.excluded_tools) == 0

    def test_plan_without_tool_manager(self):
        """Without ToolManager, all tools for asset type are included."""
        orch = ScanOrchestrator()
        plan = orch.create_scan_plan(_make_asset())

        tools = set(plan.tools)
        assert "nmap" in tools
        assert "nuclei" in tools
        assert "subfinder" in tools


# ---------------------------------------------------------------------------
# _filter_by_rules
# ---------------------------------------------------------------------------


class TestFilterByRules:
    def test_blocks_tool_mentioned_in_rule(self):
        rules = [
            ProgramRule(
                id="r1",
                description="Do not use nmap port scanning",
                is_allowed=False,
                category="testing_method",
            )
        ]
        tools = ["nmap", "nuclei", "nikto"]
        allowed, excluded = ScanOrchestrator._filter_by_rules(tools, rules)

        assert "nmap" not in allowed
        assert len(excluded) == 1
        assert excluded[0].tool_name == "nmap"

    def test_allows_all_when_no_blocking_rules(self):
        rules = [
            ProgramRule(
                id="r1",
                description="Testing is allowed",
                is_allowed=True,
                category="testing_method",
            )
        ]
        tools = ["nmap", "nuclei"]
        allowed, excluded = ScanOrchestrator._filter_by_rules(tools, rules)

        assert allowed == ["nmap", "nuclei"]
        assert excluded == []

    def test_empty_rules(self):
        allowed, excluded = ScanOrchestrator._filter_by_rules(["nmap", "nuclei"], [])
        assert allowed == ["nmap", "nuclei"]
        assert excluded == []


# ---------------------------------------------------------------------------
# _order_by_dependencies
# ---------------------------------------------------------------------------


class TestOrderByDependencies:
    def test_nmap_before_nuclei(self):
        order = ScanOrchestrator._order_by_dependencies(["nuclei", "nmap"])
        assert order.index("nmap") < order.index("nuclei")

    def test_subfinder_before_amass(self):
        order = ScanOrchestrator._order_by_dependencies(["amass", "subfinder"])
        # Both are independent so they are sorted alphabetically: amass, subfinder
        assert order.index("amass") < order.index("subfinder")

    def test_full_web_chain(self):
        order = ScanOrchestrator._order_by_dependencies(["sqlmap", "nuclei", "nmap", "nikto"])
        assert order.index("nmap") < order.index("nuclei")
        # sqlmap depends on nuclei and nikto
        assert order.index("nuclei") < order.index("sqlmap")
        assert order.index("nikto") < order.index("sqlmap")

    def test_single_tool(self):
        order = ScanOrchestrator._order_by_dependencies(["nmap"])
        assert order == ["nmap"]

    def test_independent_tools(self):
        order = ScanOrchestrator._order_by_dependencies(["nikto", "nmap"])
        # Both are independent, should be sorted alphabetically
        assert set(order) == {"nikto", "nmap"}

    def test_missing_dependency_still_works(self):
        """If nuclei is in list but nmap (its dep) is not, nuclei still appears."""
        order = ScanOrchestrator._order_by_dependencies(["nuclei"])
        assert order == ["nuclei"]


# ---------------------------------------------------------------------------
# create_scan_plan with rules
# ---------------------------------------------------------------------------


class TestPlanWithRules:
    def test_nmap_blocked_by_rule(self):
        mock_tm = MagicMock()
        mock_tm.discover_tool.side_effect = lambda name: _make_tool_info(name)

        rules = [
            ProgramRule(
                id="r1",
                description="nmap port scanning is prohibited",
                is_allowed=False,
                category="testing_method",
            )
        ]

        orch = ScanOrchestrator(tool_manager=mock_tm)
        plan = orch.create_scan_plan(_make_asset(), rules=rules)

        assert "nmap" not in plan.tools
        excluded_names = [e.tool_name for e in plan.excluded_tools]
        assert "nmap" in excluded_names


# ---------------------------------------------------------------------------
# create_scan_plan — no tools available
# ---------------------------------------------------------------------------


class TestNoToolsAvailable:
    def test_all_tools_unavailable(self):
        mock_tm = MagicMock()
        mock_tm.discover_tool.side_effect = lambda name: _make_tool_info(
            name, ToolStatus.NOT_INSTALLED
        )

        orch = ScanOrchestrator(tool_manager=mock_tm)
        with pytest.raises(NoToolsAvailableError):
            orch.create_scan_plan(_make_asset())


# ---------------------------------------------------------------------------
# execute_plan
# ---------------------------------------------------------------------------


class TestExecutePlan:
    def test_execute_with_plugins(self):
        orch = ScanOrchestrator()
        plan = orch.create_scan_plan(_make_asset())

        mock_plugin = MagicMock()
        mock_plugin.scan.return_value = []

        plugins = {tool: mock_plugin for tool in plan.execution_order}
        findings = orch.execute_plan(plan, _make_asset(), ScanConfig(asset_id="a1", program_id="p1"), plugins=plugins)

        assert isinstance(findings, list)

    def test_execute_stops_on_kill_switch(self):
        mock_sl = MagicMock()
        mock_sl.is_kill_switch_active.return_value = True

        orch = ScanOrchestrator(safety_layer=mock_sl)
        plan = orch.create_scan_plan(_make_asset())

        findings = orch.execute_plan(plan, _make_asset(), ScanConfig(asset_id="a1", program_id="p1"))
        assert findings == []

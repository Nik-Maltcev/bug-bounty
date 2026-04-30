"""Unit-тесты для ToolManager — обнаружение, установка, управление версиями."""

from unittest.mock import MagicMock, patch

import pytest

from app.core.tool_exceptions import ToolInstallError, ToolNotFoundError
from app.models.schemas import AssetType
from app.models.tool_schemas import ToolStatus
from app.services.tool_manager import ToolManager, _compare_versions


# ---------------------------------------------------------------------------
# _compare_versions
# ---------------------------------------------------------------------------


class TestCompareVersions:
    def test_equal_versions(self):
        assert _compare_versions("1.2.3", "1.2.3") is True

    def test_greater_major(self):
        assert _compare_versions("2.0.0", "1.9.9") is True

    def test_lesser_major(self):
        assert _compare_versions("1.0.0", "2.0.0") is False

    def test_greater_minor(self):
        assert _compare_versions("1.3.0", "1.2.9") is True

    def test_lesser_patch(self):
        assert _compare_versions("1.2.2", "1.2.3") is False

    def test_short_version_string(self):
        assert _compare_versions("7.80", "7.80") is True
        assert _compare_versions("7.90", "7.80") is True
        assert _compare_versions("7.70", "7.80") is False

    def test_version_with_suffix(self):
        assert _compare_versions("2.9.1-beta", "2.9.0") is True


# ---------------------------------------------------------------------------
# ToolManager.discover_tool
# ---------------------------------------------------------------------------


class TestDiscoverTool:
    @patch("app.services.tool_manager.subprocess.run")
    @patch("app.services.tool_manager.shutil.which")
    def test_tool_found_and_version_ok(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/nmap"
        mock_run.return_value = MagicMock(
            stdout="Nmap version 7.94 ( https://nmap.org )",
            stderr="",
            returncode=0,
        )

        tm = ToolManager()
        info = tm.discover_tool("nmap")

        assert info.name == "nmap"
        assert info.status == ToolStatus.INSTALLED
        assert info.version == "7.94"
        assert info.path == "/usr/bin/nmap"

    @patch("app.services.tool_manager.shutil.which")
    def test_tool_not_found(self, mock_which):
        mock_which.return_value = None

        tm = ToolManager()
        info = tm.discover_tool("nmap")

        assert info.status == ToolStatus.NOT_INSTALLED
        assert info.version is None
        assert info.path is None

    @patch("app.services.tool_manager.subprocess.run")
    @patch("app.services.tool_manager.shutil.which")
    def test_tool_outdated(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/nmap"
        mock_run.return_value = MagicMock(
            stdout="Nmap version 7.00",
            stderr="",
            returncode=0,
        )

        tm = ToolManager()
        info = tm.discover_tool("nmap")

        assert info.status == ToolStatus.OUTDATED
        assert info.version == "7.00"

    def test_unsupported_tool_raises(self):
        tm = ToolManager()
        with pytest.raises(ToolNotFoundError):
            tm.discover_tool("unknown_tool")


# ---------------------------------------------------------------------------
# ToolManager.discover_all
# ---------------------------------------------------------------------------


class TestDiscoverAll:
    @patch("app.services.tool_manager.subprocess.run")
    @patch("app.services.tool_manager.shutil.which")
    def test_returns_all_tools(self, mock_which, mock_run):
        mock_which.return_value = None
        tm = ToolManager()
        results = tm.discover_all()

        assert len(results) >= 14
        names = {r.name for r in results}
        assert "nmap" in names
        assert "subfinder" in names
        assert "sqlmap" in names


# ---------------------------------------------------------------------------
# ToolManager.install_tool
# ---------------------------------------------------------------------------


class TestInstallTool:
    @patch("app.services.tool_manager.subprocess.run")
    @patch("app.services.tool_manager.shutil.which")
    def test_install_success(self, mock_which, mock_run):
        # First call: install subprocess.run
        # Second call: discover_tool → subprocess.run for version
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(stdout="Nmap version 7.94", stderr="", returncode=0),
        ]
        mock_which.return_value = "/usr/bin/nmap"

        tm = ToolManager()
        info = tm.install_tool("nmap")
        assert info.name == "nmap"

    @patch("app.services.tool_manager.subprocess.run")
    def test_install_failure(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="E: Unable to locate package"
        )

        tm = ToolManager()
        with pytest.raises(ToolInstallError):
            tm.install_tool("nmap")

    def test_install_unsupported_tool(self):
        tm = ToolManager()
        with pytest.raises(ToolNotFoundError):
            tm.install_tool("nonexistent")


# ---------------------------------------------------------------------------
# ToolManager.get_tools_for_asset_type
# ---------------------------------------------------------------------------


class TestGetToolsForAssetType:
    @patch("app.services.tool_manager.subprocess.run")
    @patch("app.services.tool_manager.shutil.which")
    def test_web_application_tools(self, mock_which, mock_run):
        mock_which.return_value = None
        tm = ToolManager()
        tools = tm.get_tools_for_asset_type(AssetType.WEB_APPLICATION)

        names = {t.name for t in tools}
        assert "nmap" in names
        assert "nuclei" in names
        assert "subfinder" in names


# ---------------------------------------------------------------------------
# ToolManager.check_version
# ---------------------------------------------------------------------------


class TestCheckVersion:
    @patch("app.services.tool_manager.subprocess.run")
    @patch("app.services.tool_manager.shutil.which")
    def test_version_ok(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/nmap"
        mock_run.return_value = MagicMock(
            stdout="Nmap version 7.94", stderr="", returncode=0
        )

        tm = ToolManager()
        assert tm.check_version("nmap") is True

    @patch("app.services.tool_manager.shutil.which")
    def test_version_not_installed(self, mock_which):
        mock_which.return_value = None

        tm = ToolManager()
        assert tm.check_version("nmap") is False

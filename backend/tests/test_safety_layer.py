"""Unit-тесты для SafetyLayer — DNS/IP-валидация, rate limiting, Kill Switch."""

import time
from unittest.mock import MagicMock, patch

import pytest

from app.services.safety_layer import SafetyLayer, _TokenBucket


# ---------------------------------------------------------------------------
# DNS / IP validation
# ---------------------------------------------------------------------------


class TestValidateTargetDns:
    @patch("app.services.safety_layer.socket.getaddrinfo")
    def test_ip_in_scope(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.5", 0)),
        ]
        sl = SafetyLayer()
        assert sl.validate_target_dns("example.com", ["10.0.0.0/8"]) is True

    @patch("app.services.safety_layer.socket.getaddrinfo")
    def test_ip_out_of_scope(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.1", 0)),
        ]
        sl = SafetyLayer()
        assert sl.validate_target_dns("example.com", ["10.0.0.0/8"]) is False

    @patch("app.services.safety_layer.socket.getaddrinfo")
    def test_multiple_ips_all_in_scope(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.1", 0)),
            (2, 1, 6, "", ("10.0.0.2", 0)),
        ]
        sl = SafetyLayer()
        assert sl.validate_target_dns("example.com", ["10.0.0.0/8"]) is True

    @patch("app.services.safety_layer.socket.getaddrinfo")
    def test_one_ip_out_of_scope(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.1", 0)),
            (2, 1, 6, "", ("192.168.1.1", 0)),
        ]
        sl = SafetyLayer()
        assert sl.validate_target_dns("example.com", ["10.0.0.0/8"]) is False

    @patch("app.services.safety_layer.socket.getaddrinfo")
    def test_dns_resolution_failure(self, mock_getaddrinfo):
        import socket
        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")
        sl = SafetyLayer()
        assert sl.validate_target_dns("nonexistent.host", ["10.0.0.0/8"]) is False

    @patch("app.services.safety_layer.socket.getaddrinfo")
    def test_multiple_cidr_ranges(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.5", 0)),
        ]
        sl = SafetyLayer()
        assert sl.validate_target_dns(
            "example.com", ["10.0.0.0/8", "192.168.1.0/24"]
        ) is True


# ---------------------------------------------------------------------------
# Token Bucket / Rate Limiting
# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_allows_within_rate(self):
        bucket = _TokenBucket(rate=10, burst=10)
        # Should allow first 10 requests
        for _ in range(10):
            assert bucket.consume() is True

    def test_blocks_over_rate(self):
        bucket = _TokenBucket(rate=2, burst=2)
        assert bucket.consume() is True
        assert bucket.consume() is True
        # Third should be blocked (no time to refill)
        assert bucket.consume() is False

    def test_refills_over_time(self):
        bucket = _TokenBucket(rate=100, burst=100)
        # Drain all tokens
        for _ in range(100):
            bucket.consume()
        # Should be blocked
        assert bucket.consume() is False
        # Wait a bit for refill
        time.sleep(0.05)
        assert bucket.consume() is True


class TestRateLimiting:
    def test_check_rate_limit_allows(self):
        sl = SafetyLayer()
        sl.set_rate_limit(100)
        assert sl.check_rate_limit("target.com") is True

    def test_set_rate_limit(self):
        sl = SafetyLayer()
        sl.set_rate_limit(5)
        status = sl.get_safety_status()
        assert status.rate_limit_rps == 5


# ---------------------------------------------------------------------------
# Kill Switch
# ---------------------------------------------------------------------------


class TestKillSwitch:
    def test_activate_kill_switch(self):
        mock_pm = MagicMock()
        mock_pm.terminate_all.return_value = 3

        sl = SafetyLayer(process_manager=mock_pm)
        result = sl.activate_kill_switch()

        assert result.terminated_processes == 3
        assert sl.is_kill_switch_active() is True
        mock_pm.terminate_all.assert_called_once()

    def test_deactivate_kill_switch(self):
        sl = SafetyLayer()
        sl.activate_kill_switch()
        assert sl.is_kill_switch_active() is True

        sl.deactivate_kill_switch()
        assert sl.is_kill_switch_active() is False

    def test_kill_switch_with_registered_processes(self):
        sl = SafetyLayer()
        sl.register_process("scan-1", {"tool": "nmap"})
        sl.register_process("scan-2", {"tool": "nuclei"})

        result = sl.activate_kill_switch()
        assert set(result.cancelled_scans) == {"scan-1", "scan-2"}

    def test_initial_state_inactive(self):
        sl = SafetyLayer()
        assert sl.is_kill_switch_active() is False


# ---------------------------------------------------------------------------
# Process tracking & timeout
# ---------------------------------------------------------------------------


class TestProcessTracking:
    def test_register_and_check_timeout_not_exceeded(self):
        sl = SafetyLayer()
        sl.register_process("scan-1", {"tool": "nmap"})
        assert sl.check_process_timeout("scan-1", timeout_seconds=3600) is False

    def test_check_timeout_exceeded(self):
        sl = SafetyLayer()
        sl.register_process("scan-1", {"tool": "nmap"})
        # Hack: set started_at to the past
        with sl._lock:
            sl._active_processes["scan-1"].started_at = time.monotonic() - 100
        assert sl.check_process_timeout("scan-1", timeout_seconds=50) is True

    def test_check_timeout_unknown_scan(self):
        sl = SafetyLayer()
        assert sl.check_process_timeout("nonexistent", timeout_seconds=10) is False


# ---------------------------------------------------------------------------
# Safety status
# ---------------------------------------------------------------------------


class TestSafetyStatus:
    def test_default_status(self):
        sl = SafetyLayer()
        status = sl.get_safety_status()

        assert status.kill_switch_active is False
        assert status.active_processes_count == 0
        assert status.rate_limit_rps == 10
        assert status.active_scans == []

    def test_status_with_processes(self):
        sl = SafetyLayer()
        sl.register_process("scan-1", {})
        sl.register_process("scan-2", {})

        status = sl.get_safety_status()
        assert status.active_processes_count == 2
        assert set(status.active_scans) == {"scan-1", "scan-2"}

"""Слой безопасности — DNS/IP-валидация scope, rate limiting, Kill Switch.

Централизованная проверка безопасности перед каждым запуском инструмента.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from datetime import datetime, timezone

from app.models.tool_schemas import KillSwitchResult, SafetyStatus

logger = logging.getLogger(__name__)


class _TokenBucket:
    """Простой token-bucket rate limiter на основе time.monotonic()."""

    def __init__(self, rate: int, burst: int | None = None) -> None:
        self._rate = rate
        self._burst = burst or rate
        self._tokens = float(self._burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    @property
    def rate(self) -> int:
        return self._rate

    def set_rate(self, rate: int) -> None:
        with self._lock:
            self._rate = rate
            self._burst = rate
            self._tokens = float(rate)
            self._last_refill = time.monotonic()

    def consume(self) -> bool:
        """Пытается потребить 1 токен. Возвращает True если разрешено."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self._burst),
                self._tokens + elapsed * self._rate,
            )
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class SafetyLayer:
    """Слой безопасности: scope-валидация, rate limiting, Kill Switch."""

    def __init__(
        self,
        process_manager=None,
    ) -> None:
        self._kill_switch_active: bool = False
        self._rate_limiters: dict[str, _TokenBucket] = {}
        self._default_rps: int = 10
        self._global_limiter = _TokenBucket(self._default_rps)
        self._active_processes: dict[str, _ProcessHandle] = {}
        self._lock = threading.Lock()
        self._process_manager = process_manager

    # ------------------------------------------------------------------
    # DNS / IP scope validation
    # ------------------------------------------------------------------

    def validate_target_dns(
        self, target: str, allowed_ips: list[str]
    ) -> bool:
        """DNS-резолвинг целевого хоста + проверка IP в CIDR-диапазонах scope.

        Args:
            target: hostname или IP-адрес.
            allowed_ips: список CIDR-диапазонов (напр. ["10.0.0.0/8", "192.168.1.0/24"]).

        Returns:
            True если все resolved IP входят в allowed_ips, False иначе.
        """
        resolved = self._resolve_target(target)
        if not resolved:
            logger.warning("DNS resolution failed for target: %s", target)
            return False

        networks = []
        for cidr in allowed_ips:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid CIDR: %s", cidr)

        for ip_str in resolved:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                logger.warning("Invalid resolved IP: %s", ip_str)
                return False

            if not any(ip in net for net in networks):
                logger.warning(
                    "IP %s (from %s) is outside allowed scope", ip_str, target
                )
                return False

        return True

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def check_rate_limit(self, target: str) -> bool:
        """Проверяет, не превышен ли лимит запросов к цели."""
        return self._global_limiter.consume()

    def set_rate_limit(self, requests_per_second: int) -> None:
        """Устанавливает лимит запросов."""
        self._default_rps = requests_per_second
        self._global_limiter.set_rate(requests_per_second)

    # ------------------------------------------------------------------
    # Kill Switch
    # ------------------------------------------------------------------

    def activate_kill_switch(self) -> KillSwitchResult:
        """Немедленно завершает все процессы, обновляет статусы сканирований."""
        self._kill_switch_active = True

        terminated = 0
        cancelled_scans: list[str] = []

        # Terminate via ProcessManager if available
        if self._process_manager is not None:
            terminated = self._process_manager.terminate_all()

        # Terminate locally tracked processes
        with self._lock:
            for scan_id, handle in self._active_processes.items():
                cancelled_scans.append(scan_id)
            self._active_processes.clear()

        logger.warning(
            "Kill switch activated: terminated=%d, cancelled_scans=%s",
            terminated,
            cancelled_scans,
        )

        return KillSwitchResult(
            terminated_processes=terminated,
            cancelled_scans=cancelled_scans,
            timestamp=datetime.now(timezone.utc),
        )

    def is_kill_switch_active(self) -> bool:
        """Проверяет, активен ли Kill Switch."""
        return self._kill_switch_active

    def deactivate_kill_switch(self) -> None:
        """Деактивирует Kill Switch."""
        self._kill_switch_active = False
        logger.info("Kill switch deactivated")

    # ------------------------------------------------------------------
    # Process tracking
    # ------------------------------------------------------------------

    def register_process(self, scan_id: str, process_info: dict) -> None:
        """Регистрирует процесс для мониторинга и Kill Switch."""
        with self._lock:
            self._active_processes[scan_id] = _ProcessHandle(
                scan_id=scan_id,
                started_at=time.monotonic(),
                info=process_info,
            )

    def check_process_timeout(self, scan_id: str, timeout_seconds: int) -> bool:
        """Проверяет, не превышен ли таймаут процесса.

        Returns:
            True если таймаут превышен, False иначе.
        """
        with self._lock:
            handle = self._active_processes.get(scan_id)
        if handle is None:
            return False
        elapsed = time.monotonic() - handle.started_at
        return elapsed > timeout_seconds

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_safety_status(self) -> SafetyStatus:
        """Возвращает текущее состояние ограничений безопасности."""
        with self._lock:
            active_scans = list(self._active_processes.keys())
        return SafetyStatus(
            kill_switch_active=self._kill_switch_active,
            active_processes_count=len(active_scans),
            rate_limit_rps=self._default_rps,
            active_scans=active_scans,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_target(target: str) -> list[str]:
        """Резолвит hostname в список IP-адресов."""
        try:
            results = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list({r[4][0] for r in results})
            return ips
        except socket.gaierror:
            logger.warning("Cannot resolve hostname: %s", target)
            return []


class _ProcessHandle:
    """Внутреннее представление отслеживаемого процесса."""

    __slots__ = ("scan_id", "started_at", "info")

    def __init__(self, scan_id: str, started_at: float, info: dict) -> None:
        self.scan_id = scan_id
        self.started_at = started_at
        self.info = info

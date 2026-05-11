"""Rate Limiter для AI-запросов.

Ограничивает частоту HTTP-запросов к целевой системе.
По умолчанию: 5 запросов в секунду.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class RateLimiterStats:
    """Статистика rate limiter."""

    total_requests: int = 0
    total_wait_time_ms: int = 0
    requests_per_second: float = 0.0


class RateLimiter:
    """Async-совместимый rate limiter.

    Использует token bucket алгоритм для ограничения частоты запросов.
    """

    DEFAULT_RATE = 5.0  # запросов в секунду

    def __init__(self, requests_per_second: float = DEFAULT_RATE) -> None:
        """Инициализация rate limiter.

        Args:
            requests_per_second: максимальное количество запросов в секунду.
        """
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")

        self._rate = requests_per_second
        self._interval = 1.0 / requests_per_second
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()
        self._total_requests = 0
        self._total_wait_time_ms = 0
        self._start_time = time.monotonic()

    @property
    def rate(self) -> float:
        """Текущий лимит запросов в секунду."""
        return self._rate

    @property
    def request_count(self) -> int:
        """Общее количество выполненных запросов."""
        return self._total_requests

    async def acquire(self) -> float:
        """Ожидает разрешения на выполнение запроса.

        Returns:
            Время ожидания в секундах (0 если ожидание не требовалось).
        """
        async with self._lock:
            now = time.monotonic()
            time_since_last = now - self._last_request_time
            wait_time = self._interval - time_since_last

            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self._total_wait_time_ms += int(wait_time * 1000)
            else:
                wait_time = 0

            self._last_request_time = time.monotonic()
            self._total_requests += 1

            return wait_time

    def acquire_sync(self) -> float:
        """Синхронная версия acquire для использования без asyncio.

        Returns:
            Время ожидания в секундах.
        """
        now = time.monotonic()
        time_since_last = now - self._last_request_time
        wait_time = self._interval - time_since_last

        if wait_time > 0:
            time.sleep(wait_time)
            self._total_wait_time_ms += int(wait_time * 1000)
        else:
            wait_time = 0

        self._last_request_time = time.monotonic()
        self._total_requests += 1

        return wait_time

    def try_acquire(self) -> bool:
        """Пытается получить разрешение без ожидания.

        Returns:
            True если разрешение получено, False если нужно ждать.
        """
        now = time.monotonic()
        time_since_last = now - self._last_request_time

        if time_since_last >= self._interval:
            self._last_request_time = now
            self._total_requests += 1
            return True

        return False

    def get_stats(self) -> RateLimiterStats:
        """Возвращает статистику rate limiter."""
        elapsed = time.monotonic() - self._start_time
        actual_rate = self._total_requests / elapsed if elapsed > 0 else 0.0

        return RateLimiterStats(
            total_requests=self._total_requests,
            total_wait_time_ms=self._total_wait_time_ms,
            requests_per_second=round(actual_rate, 2),
        )

    def reset(self) -> None:
        """Сбрасывает счётчики и состояние."""
        self._last_request_time = 0.0
        self._total_requests = 0
        self._total_wait_time_ms = 0
        self._start_time = time.monotonic()

    def update_rate(self, new_rate: float) -> None:
        """Обновляет лимит запросов в секунду.

        Args:
            new_rate: новый лимит запросов в секунду.
        """
        if new_rate <= 0:
            raise ValueError("new_rate must be positive")

        self._rate = new_rate
        self._interval = 1.0 / new_rate
        logger.info("Rate limiter updated to %.1f req/s", new_rate)


class MultiTargetRateLimiter:
    """Rate limiter с отдельными лимитами для разных целей.

    Позволяет устанавливать разные лимиты для разных доменов/хостов.
    """

    def __init__(self, default_rate: float = RateLimiter.DEFAULT_RATE) -> None:
        """Инициализация multi-target rate limiter.

        Args:
            default_rate: лимит по умолчанию для новых целей.
        """
        self._default_rate = default_rate
        self._limiters: dict[str, RateLimiter] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, target: str) -> float:
        """Ожидает разрешения для конкретной цели.

        Args:
            target: идентификатор цели (домен, хост).

        Returns:
            Время ожидания в секундах.
        """
        async with self._lock:
            if target not in self._limiters:
                self._limiters[target] = RateLimiter(self._default_rate)

        return await self._limiters[target].acquire()

    def set_target_rate(self, target: str, rate: float) -> None:
        """Устанавливает лимит для конкретной цели.

        Args:
            target: идентификатор цели.
            rate: лимит запросов в секунду.
        """
        if target in self._limiters:
            self._limiters[target].update_rate(rate)
        else:
            self._limiters[target] = RateLimiter(rate)

    def get_target_stats(self, target: str) -> RateLimiterStats | None:
        """Возвращает статистику для конкретной цели."""
        limiter = self._limiters.get(target)
        return limiter.get_stats() if limiter else None

    def get_all_stats(self) -> dict[str, RateLimiterStats]:
        """Возвращает статистику для всех целей."""
        return {target: limiter.get_stats() for target, limiter in self._limiters.items()}

    def get_total_requests(self) -> int:
        """Возвращает общее количество запросов по всем целям."""
        return sum(limiter.request_count for limiter in self._limiters.values())

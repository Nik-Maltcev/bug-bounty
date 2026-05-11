"""Тесты для RateLimiter — ограничение частоты запросов."""

import asyncio
import time

import pytest

from app.services.ai.rate_limiter import MultiTargetRateLimiter, RateLimiter


class TestRateLimiter:
    """Тесты RateLimiter."""

    def test_init_default_rate(self):
        """Инициализация с дефолтным rate (5 req/s)."""
        limiter = RateLimiter()
        assert limiter.rate == 5.0
        assert limiter.request_count == 0

    def test_init_custom_rate(self):
        """Инициализация с кастомным rate."""
        limiter = RateLimiter(requests_per_second=10.0)
        assert limiter.rate == 10.0

    def test_init_invalid_rate_raises(self):
        """Невалидный rate вызывает ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            RateLimiter(requests_per_second=0)

        with pytest.raises(ValueError, match="must be positive"):
            RateLimiter(requests_per_second=-1)

    def test_acquire_sync_increments_counter(self):
        """acquire_sync увеличивает счётчик запросов."""
        limiter = RateLimiter(requests_per_second=100)  # высокий rate для быстрого теста
        assert limiter.request_count == 0

        limiter.acquire_sync()
        assert limiter.request_count == 1

        limiter.acquire_sync()
        assert limiter.request_count == 2

    def test_acquire_sync_respects_rate_limit(self):
        """acquire_sync соблюдает интервал между запросами."""
        limiter = RateLimiter(requests_per_second=10)  # 100ms между запросами

        start = time.monotonic()
        limiter.acquire_sync()
        limiter.acquire_sync()
        limiter.acquire_sync()
        elapsed = time.monotonic() - start

        # 3 запроса при 10 req/s = минимум 200ms (2 интервала)
        assert elapsed >= 0.18  # небольшой допуск

    def test_try_acquire_without_waiting(self):
        """try_acquire возвращает False если нужно ждать."""
        limiter = RateLimiter(requests_per_second=2)  # 500ms между запросами

        # Первый запрос — успех
        assert limiter.try_acquire() is True
        assert limiter.request_count == 1

        # Сразу второй — нужно ждать
        assert limiter.try_acquire() is False
        assert limiter.request_count == 1  # счётчик не увеличился

    def test_try_acquire_after_interval(self):
        """try_acquire успешен после истечения интервала."""
        limiter = RateLimiter(requests_per_second=20)  # 50ms между запросами

        assert limiter.try_acquire() is True
        time.sleep(0.06)  # ждём чуть больше интервала
        assert limiter.try_acquire() is True
        assert limiter.request_count == 2

    def test_get_stats(self):
        """get_stats возвращает корректную статистику."""
        limiter = RateLimiter(requests_per_second=100)

        limiter.acquire_sync()
        limiter.acquire_sync()
        limiter.acquire_sync()

        stats = limiter.get_stats()
        assert stats.total_requests == 3
        assert stats.requests_per_second > 0

    def test_reset(self):
        """reset сбрасывает счётчики."""
        limiter = RateLimiter(requests_per_second=100)

        limiter.acquire_sync()
        limiter.acquire_sync()
        assert limiter.request_count == 2

        limiter.reset()
        assert limiter.request_count == 0

    def test_update_rate(self):
        """update_rate изменяет лимит."""
        limiter = RateLimiter(requests_per_second=5)
        assert limiter.rate == 5.0

        limiter.update_rate(10.0)
        assert limiter.rate == 10.0

    def test_update_rate_invalid_raises(self):
        """update_rate с невалидным значением вызывает ValueError."""
        limiter = RateLimiter()

        with pytest.raises(ValueError, match="must be positive"):
            limiter.update_rate(0)


class TestRateLimiterAsync:
    """Async-тесты RateLimiter."""

    @pytest.mark.asyncio
    async def test_acquire_async(self):
        """acquire работает в async контексте."""
        limiter = RateLimiter(requests_per_second=100)

        wait_time = await limiter.acquire()
        assert limiter.request_count == 1
        assert wait_time >= 0

    @pytest.mark.asyncio
    async def test_acquire_async_respects_rate(self):
        """acquire соблюдает rate limit в async."""
        limiter = RateLimiter(requests_per_second=10)

        start = time.monotonic()
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        assert elapsed >= 0.18


class TestMultiTargetRateLimiter:
    """Тесты MultiTargetRateLimiter."""

    def test_init_default_rate(self):
        """Инициализация с дефолтным rate."""
        limiter = MultiTargetRateLimiter()
        assert limiter._default_rate == 5.0

    def test_init_custom_rate(self):
        """Инициализация с кастомным rate."""
        limiter = MultiTargetRateLimiter(default_rate=10.0)
        assert limiter._default_rate == 10.0

    @pytest.mark.asyncio
    async def test_acquire_creates_limiter_for_target(self):
        """acquire создаёт отдельный limiter для каждой цели."""
        limiter = MultiTargetRateLimiter(default_rate=100)

        await limiter.acquire("target-a")
        await limiter.acquire("target-b")

        assert "target-a" in limiter._limiters
        assert "target-b" in limiter._limiters

    @pytest.mark.asyncio
    async def test_acquire_reuses_limiter_for_same_target(self):
        """acquire переиспользует limiter для той же цели."""
        limiter = MultiTargetRateLimiter(default_rate=100)

        await limiter.acquire("target-a")
        await limiter.acquire("target-a")
        await limiter.acquire("target-a")

        assert len(limiter._limiters) == 1
        assert limiter._limiters["target-a"].request_count == 3

    def test_set_target_rate(self):
        """set_target_rate устанавливает кастомный rate для цели."""
        limiter = MultiTargetRateLimiter(default_rate=5)

        limiter.set_target_rate("slow-target", 1.0)
        limiter.set_target_rate("fast-target", 20.0)

        assert limiter._limiters["slow-target"].rate == 1.0
        assert limiter._limiters["fast-target"].rate == 20.0

    def test_get_target_stats(self):
        """get_target_stats возвращает статистику для цели."""
        limiter = MultiTargetRateLimiter(default_rate=100)
        limiter.set_target_rate("target-a", 100)
        limiter._limiters["target-a"].acquire_sync()

        stats = limiter.get_target_stats("target-a")
        assert stats is not None
        assert stats.total_requests == 1

    def test_get_target_stats_unknown_target(self):
        """get_target_stats возвращает None для неизвестной цели."""
        limiter = MultiTargetRateLimiter()
        assert limiter.get_target_stats("unknown") is None

    def test_get_all_stats(self):
        """get_all_stats возвращает статистику для всех целей."""
        limiter = MultiTargetRateLimiter(default_rate=100)
        limiter.set_target_rate("target-a", 100)
        limiter.set_target_rate("target-b", 100)
        limiter._limiters["target-a"].acquire_sync()
        limiter._limiters["target-b"].acquire_sync()
        limiter._limiters["target-b"].acquire_sync()

        all_stats = limiter.get_all_stats()
        assert len(all_stats) == 2
        assert all_stats["target-a"].total_requests == 1
        assert all_stats["target-b"].total_requests == 2

    def test_get_total_requests(self):
        """get_total_requests возвращает сумму по всем целям."""
        limiter = MultiTargetRateLimiter(default_rate=100)
        limiter.set_target_rate("target-a", 100)
        limiter.set_target_rate("target-b", 100)
        limiter._limiters["target-a"].acquire_sync()
        limiter._limiters["target-b"].acquire_sync()
        limiter._limiters["target-b"].acquire_sync()

        assert limiter.get_total_requests() == 3

    @pytest.mark.asyncio
    async def test_independent_rate_limits(self):
        """Разные цели имеют независимые rate limits."""
        limiter = MultiTargetRateLimiter(default_rate=100)

        # Быстрые запросы к разным целям не блокируют друг друга
        start = time.monotonic()
        await limiter.acquire("target-a")
        await limiter.acquire("target-b")
        await limiter.acquire("target-c")
        elapsed = time.monotonic() - start

        # Все запросы должны выполниться быстро (разные цели)
        assert elapsed < 0.1

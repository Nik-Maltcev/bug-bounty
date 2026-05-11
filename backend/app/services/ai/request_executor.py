"""RequestExecutor — выполнение AI-сгенерированных HTTP-запросов.

Использует ProcessManager для безопасного выполнения curl/httpx
с rate limiting и ограничением размера ответа.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from datetime import UTC, datetime
from urllib.parse import urlparse

from app.models.ai_scan_schemas import AIRequest, AIRequestResult
from app.services.ai.rate_limiter import RateLimiter
from app.services.process_manager import ProcessManager

logger = logging.getLogger(__name__)


class RequestExecutor:
    """Выполняет AI-сгенерированные HTTP-запросы через ProcessManager."""

    MAX_BODY_SIZE = 100 * 1024  # 100 KB
    DEFAULT_TIMEOUT = 30  # секунд
    DEFAULT_RATE_LIMIT = 5.0  # запросов в секунду

    def __init__(
        self,
        process_manager: ProcessManager | None = None,
        rate_limiter: RateLimiter | None = None,
        rate_limit: float = DEFAULT_RATE_LIMIT,
    ) -> None:
        """Инициализация executor.

        Args:
            process_manager: менеджер процессов (создаётся если не передан).
            rate_limiter: rate limiter (создаётся если не передан).
            rate_limit: лимит запросов в секунду.
        """
        self._process_manager = process_manager or ProcessManager()
        self._rate_limiter = rate_limiter or RateLimiter(rate_limit)
        self._request_count = 0

    @property
    def request_count(self) -> int:
        """Количество выполненных запросов."""
        return self._request_count

    def execute(self, request: AIRequest) -> AIRequestResult:
        """Выполняет HTTP-запрос синхронно.

        Args:
            request: AI-сгенерированный запрос.

        Returns:
            Результат выполнения запроса.
        """
        # Rate limiting
        self._rate_limiter.acquire_sync()

        # Формируем команду curl
        command = self._build_curl_command(request)
        logger.debug("Executing: %s", " ".join(command))

        # Выполняем через ProcessManager
        timeout = request.timeout_seconds or self.DEFAULT_TIMEOUT
        result = self._process_manager.execute(command, timeout_seconds=timeout)

        self._request_count += 1

        # Парсим результат
        return self._parse_curl_output(request, result)

    async def execute_async(self, request: AIRequest) -> AIRequestResult:
        """Выполняет HTTP-запрос асинхронно.

        Args:
            request: AI-сгенерированный запрос.

        Returns:
            Результат выполнения запроса.
        """
        # Rate limiting
        await self._rate_limiter.acquire()

        # Формируем команду curl
        command = self._build_curl_command(request)
        logger.debug("Executing async: %s", " ".join(command))

        # Выполняем через ProcessManager (синхронно, но после async rate limit)
        timeout = request.timeout_seconds or self.DEFAULT_TIMEOUT
        result = self._process_manager.execute(command, timeout_seconds=timeout)

        self._request_count += 1

        # Парсим результат
        return self._parse_curl_output(request, result)

    def _build_curl_command(self, request: AIRequest) -> list[str]:
        """Формирует команду curl из AIRequest.

        Args:
            request: AI-запрос.

        Returns:
            Список аргументов команды.
        """
        command = [
            "curl",
            "-s",  # silent
            "-S",  # show errors
            "-i",  # include headers in output
            "-X", request.method,
            "--max-time", str(request.timeout_seconds or self.DEFAULT_TIMEOUT),
            "--max-filesize", str(self.MAX_BODY_SIZE),
            "-w", "\n__CURL_INFO__\nhttp_code:%{http_code}\ntime_total:%{time_total}\n",
        ]

        # Добавляем заголовки
        for name, value in request.headers.items():
            # Экранируем значения заголовков
            safe_value = value.replace('"', '\\"')
            command.extend(["-H", f"{name}: {safe_value}"])

        # Добавляем тело запроса
        if request.body:
            command.extend(["-d", request.body])

        # URL должен быть последним
        command.append(request.url)

        return command

    def _parse_curl_output(
        self, request: AIRequest, result
    ) -> AIRequestResult:
        """Парсит вывод curl в AIRequestResult.

        Args:
            request: исходный запрос.
            result: результат ProcessManager.execute().

        Returns:
            Структурированный результат.
        """
        executed_at = datetime.now(UTC)

        # Проверяем на ошибки
        if result.exit_code != 0 and not result.timed_out:
            return AIRequestResult(
                request_id=request.id,
                hypothesis_id=request.hypothesis_id,
                status_code=None,
                response_headers={},
                response_body="",
                duration_ms=int(result.duration_seconds * 1000),
                error=result.stderr or f"curl exit code: {result.exit_code}",
                executed_at=executed_at,
            )

        if result.timed_out:
            return AIRequestResult(
                request_id=request.id,
                hypothesis_id=request.hypothesis_id,
                status_code=None,
                response_headers={},
                response_body="",
                duration_ms=int(result.duration_seconds * 1000),
                error="Request timed out",
                executed_at=executed_at,
            )

        # Парсим вывод curl
        output = result.stdout
        status_code = None
        duration_ms = int(result.duration_seconds * 1000)
        headers: dict[str, str] = {}
        body = ""

        # Извлекаем информацию из __CURL_INFO__
        info_match = re.search(r"__CURL_INFO__\n(.+)", output, re.DOTALL)
        if info_match:
            info_text = info_match.group(1)
            code_match = re.search(r"http_code:(\d+)", info_text)
            if code_match:
                status_code = int(code_match.group(1))

            time_match = re.search(r"time_total:([\d.]+)", info_text)
            if time_match:
                duration_ms = int(float(time_match.group(1)) * 1000)

            # Убираем info из output
            output = output[:info_match.start()]

        # Разделяем headers и body
        # curl -i выводит: HTTP/1.1 200 OK\r\n...headers...\r\n\r\nbody
        parts = re.split(r"\r?\n\r?\n", output, maxsplit=1)
        if len(parts) >= 1:
            headers_text = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            # Парсим заголовки
            for line in headers_text.split("\n"):
                line = line.strip()
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip()] = value.strip()
                elif line.startswith("HTTP/"):
                    # HTTP/1.1 200 OK
                    match = re.match(r"HTTP/[\d.]+ (\d+)", line)
                    if match and status_code is None:
                        status_code = int(match.group(1))

        # Обрезаем body до MAX_BODY_SIZE
        if len(body) > self.MAX_BODY_SIZE:
            body = body[:self.MAX_BODY_SIZE] + "\n[TRUNCATED]"

        return AIRequestResult(
            request_id=request.id,
            hypothesis_id=request.hypothesis_id,
            status_code=status_code,
            response_headers=headers,
            response_body=body,
            duration_ms=duration_ms,
            error=None,
            executed_at=executed_at,
        )

    def update_rate_limit(self, new_rate: float) -> None:
        """Обновляет rate limit.

        Args:
            new_rate: новый лимит запросов в секунду.
        """
        self._rate_limiter.update_rate(new_rate)

    def get_stats(self) -> dict:
        """Возвращает статистику выполнения."""
        limiter_stats = self._rate_limiter.get_stats()
        return {
            "total_requests": self._request_count,
            "rate_limiter": {
                "total_requests": limiter_stats.total_requests,
                "total_wait_time_ms": limiter_stats.total_wait_time_ms,
                "actual_rate": limiter_stats.requests_per_second,
            },
        }


class HttpxExecutor(RequestExecutor):
    """Альтернативный executor, использующий httpx вместо curl."""

    def _build_curl_command(self, request: AIRequest) -> list[str]:
        """Формирует команду httpx из AIRequest.

        httpx CLI имеет другой синтаксис, но мы адаптируем его.
        """
        command = [
            "httpx",
            "-silent",
            "-no-color",
            "-include-response",
            "-timeout", str(request.timeout_seconds or self.DEFAULT_TIMEOUT),
            "-method", request.method,
        ]

        # Добавляем заголовки
        for name, value in request.headers.items():
            command.extend(["-H", f"{name}: {value}"])

        # Добавляем тело запроса
        if request.body:
            command.extend(["-body", request.body])

        # URL
        command.extend(["-u", request.url])

        return command


def extract_domain(url: str) -> str:
    """Извлекает домен из URL для rate limiting."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]

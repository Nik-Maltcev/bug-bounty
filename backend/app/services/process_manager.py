"""Менеджер процессов — безопасный запуск и управление дочерними процессами.

Использует subprocess.Popen для запуска внешних инструментов безопасности
с буферизацией stdout/stderr, таймаутами и очисткой ресурсов.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from app.models.tool_schemas import ProcessInfo, ProcessResult

logger = logging.getLogger(__name__)


class ProcessManager:
    """Безопасный запуск и управление дочерними процессами инструментов."""

    def __init__(self) -> None:
        self._active_processes: dict[str, _ActiveProcess] = {}
        self._lock = threading.Lock()

    def execute(
        self,
        command: list[str],
        timeout_seconds: int = 1800,
        working_dir: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ProcessResult:
        """Запускает команду как дочерний процесс.

        - Перенаправляет stdout/stderr в буфер
        - Применяет таймаут (kill при превышении)
        - Очищает ресурсы при завершении
        """
        start_time = time.monotonic()
        timed_out = False

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=working_dir,
                env=env,
            )
        except FileNotFoundError:
            duration = time.monotonic() - start_time
            logger.error("Command not found: %s", command)
            return ProcessResult(
                stdout="",
                stderr=f"Command not found: {command[0]}",
                exit_code=-1,
                timed_out=False,
                duration_seconds=round(duration, 3),
            )
        except OSError as exc:
            duration = time.monotonic() - start_time
            logger.error("OS error launching process: %s", exc)
            return ProcessResult(
                stdout="",
                stderr=str(exc),
                exit_code=-1,
                timed_out=False,
                duration_seconds=round(duration, 3),
            )

        process_id = uuid.uuid4().hex[:12]

        with self._lock:
            self._active_processes[process_id] = _ActiveProcess(
                process=process,
                process_id=process_id,
                command=command,
                scan_id="",
                tool_name="",
                started_at=datetime.now(timezone.utc),
            )

        try:
            stdout_bytes, stderr_bytes = process.communicate(
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            logger.warning(
                "Process %s timed out after %ds, killing...",
                process_id,
                timeout_seconds,
            )
            process.kill()
            stdout_bytes, stderr_bytes = process.communicate()
        finally:
            with self._lock:
                self._active_processes.pop(process_id, None)

        duration = time.monotonic() - start_time

        stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

        return ProcessResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=process.returncode,
            timed_out=timed_out,
            duration_seconds=round(duration, 3),
        )

    def register_process(
        self,
        scan_id: str,
        tool_name: str,
        process: subprocess.Popen,  # type: ignore[type-arg]
    ) -> str:
        """Регистрирует внешний процесс для отслеживания и Kill Switch.

        Returns:
            process_id — уникальный идентификатор зарегистрированного процесса.
        """
        process_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._active_processes[process_id] = _ActiveProcess(
                process=process,
                process_id=process_id,
                command=[],
                scan_id=scan_id,
                tool_name=tool_name,
                started_at=datetime.now(timezone.utc),
            )
        logger.info(
            "Registered process %s (scan=%s, tool=%s)",
            process_id,
            scan_id,
            tool_name,
        )
        return process_id

    def terminate(self, process_id: str) -> bool:
        """Завершает конкретный процесс (kill).

        Returns:
            True если процесс был найден и завершён, False если не найден.
        """
        with self._lock:
            active = self._active_processes.pop(process_id, None)

        if active is None:
            return False

        _kill_process(active.process)
        logger.info("Terminated process %s", process_id)
        return True

    def terminate_all(self) -> int:
        """Завершает все активные процессы.

        Returns:
            Количество завершённых процессов.
        """
        with self._lock:
            processes = list(self._active_processes.values())
            self._active_processes.clear()

        for active in processes:
            _kill_process(active.process)

        count = len(processes)
        if count:
            logger.info("Terminated all %d active processes", count)
        return count

    def get_active_processes(self) -> list[ProcessInfo]:
        """Возвращает список активных процессов."""
        with self._lock:
            return [
                ProcessInfo(
                    process_id=ap.process_id,
                    tool_name=ap.tool_name,
                    scan_id=ap.scan_id,
                    started_at=ap.started_at,
                    command=ap.command,
                )
                for ap in self._active_processes.values()
            ]


class _ActiveProcess:
    """Внутреннее представление активного процесса."""

    __slots__ = (
        "process",
        "process_id",
        "command",
        "scan_id",
        "tool_name",
        "started_at",
    )

    def __init__(
        self,
        process: subprocess.Popen,  # type: ignore[type-arg]
        process_id: str,
        command: list[str],
        scan_id: str,
        tool_name: str,
        started_at: datetime,
    ) -> None:
        self.process = process
        self.process_id = process_id
        self.command = command
        self.scan_id = scan_id
        self.tool_name = tool_name
        self.started_at = started_at


def _kill_process(process: subprocess.Popen) -> None:  # type: ignore[type-arg]
    """Принудительно завершает процесс (kill)."""
    try:
        process.kill()
        process.wait(timeout=5)
    except Exception:
        pass

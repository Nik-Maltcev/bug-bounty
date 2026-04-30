"""Тесты для ProcessManager — менеджера процессов."""

import subprocess
import sys
import time

import pytest

from app.services.process_manager import ProcessManager


class TestProcessManagerExecute:
    """Тесты метода execute."""

    def test_execute_simple_command(self):
        """Успешный запуск простой команды."""
        pm = ProcessManager()
        result = pm.execute(
            [sys.executable, "-c", "print('hello')"],
            timeout_seconds=10,
        )
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.timed_out is False
        assert result.duration_seconds > 0

    def test_execute_captures_stderr(self):
        """Захват stderr при ошибке."""
        pm = ProcessManager()
        result = pm.execute(
            [sys.executable, "-c", "import sys; sys.stderr.write('oops')"],
            timeout_seconds=10,
        )
        assert "oops" in result.stderr

    def test_execute_nonzero_exit_code(self):
        """Ненулевой код возврата."""
        pm = ProcessManager()
        result = pm.execute(
            [sys.executable, "-c", "import sys; sys.exit(42)"],
            timeout_seconds=10,
        )
        assert result.exit_code == 42
        assert result.timed_out is False

    def test_execute_timeout(self):
        """Таймаут процесса — процесс убивается."""
        pm = ProcessManager()
        result = pm.execute(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            timeout_seconds=1,
        )
        assert result.timed_out is True
        assert result.duration_seconds >= 1.0

    def test_execute_command_not_found(self):
        """Команда не найдена — возвращает exit_code=-1."""
        pm = ProcessManager()
        result = pm.execute(
            ["nonexistent_command_xyz_12345"],
            timeout_seconds=5,
        )
        assert result.exit_code == -1
        assert "not found" in result.stderr.lower() or "Command not found" in result.stderr

    def test_execute_with_working_dir(self, tmp_path):
        """Запуск с указанной рабочей директорией."""
        pm = ProcessManager()
        result = pm.execute(
            [sys.executable, "-c", "import os; print(os.getcwd())"],
            timeout_seconds=10,
            working_dir=str(tmp_path),
        )
        assert result.exit_code == 0
        assert str(tmp_path) in result.stdout.replace("/", "\\").replace("\\", "/") or \
               tmp_path.name in result.stdout

    def test_execute_with_env(self):
        """Запуск с пользовательскими переменными окружения."""
        import os

        env = os.environ.copy()
        env["TEST_PM_VAR"] = "test_value_42"
        pm = ProcessManager()
        result = pm.execute(
            [sys.executable, "-c", "import os; print(os.environ.get('TEST_PM_VAR', ''))"],
            timeout_seconds=10,
            env=env,
        )
        assert result.exit_code == 0
        assert "test_value_42" in result.stdout

    def test_execute_cleans_up_active_processes(self):
        """После завершения процесс удаляется из списка активных."""
        pm = ProcessManager()
        pm.execute(
            [sys.executable, "-c", "print('done')"],
            timeout_seconds=10,
        )
        assert len(pm.get_active_processes()) == 0


class TestProcessManagerTerminate:
    """Тесты методов terminate и terminate_all."""

    def test_terminate_unknown_process(self):
        """Завершение несуществующего процесса возвращает False."""
        pm = ProcessManager()
        assert pm.terminate("nonexistent_id") is False

    def test_terminate_registered_process(self):
        """Завершение зарегистрированного процесса."""
        pm = ProcessManager()
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            pid = pm.register_process("scan-1", "nmap", proc)
            assert pm.terminate(pid) is True
            assert len(pm.get_active_processes()) == 0
            # Process should be dead
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
            proc.wait()
            raise

    def test_terminate_all(self):
        """terminate_all завершает все зарегистрированные процессы."""
        pm = ProcessManager()
        procs = []
        for i in range(3):
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            procs.append(proc)
            pm.register_process(f"scan-{i}", f"tool-{i}", proc)

        try:
            assert len(pm.get_active_processes()) == 3
            count = pm.terminate_all()
            assert count == 3
            assert len(pm.get_active_processes()) == 0
            # All processes should be dead
            for proc in procs:
                proc.wait(timeout=5)
        except Exception:
            for proc in procs:
                proc.kill()
                proc.wait()
            raise

    def test_terminate_all_empty(self):
        """terminate_all без активных процессов возвращает 0."""
        pm = ProcessManager()
        assert pm.terminate_all() == 0


class TestProcessManagerGetActiveProcesses:
    """Тесты метода get_active_processes."""

    def test_get_active_processes_empty(self):
        """Пустой список при отсутствии процессов."""
        pm = ProcessManager()
        assert pm.get_active_processes() == []

    def test_get_active_processes_returns_info(self):
        """Возвращает ProcessInfo для зарегистрированных процессов."""
        pm = ProcessManager()
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            pm.register_process("scan-abc", "nuclei", proc)
            active = pm.get_active_processes()
            assert len(active) == 1
            assert active[0].scan_id == "scan-abc"
            assert active[0].tool_name == "nuclei"
        finally:
            pm.terminate_all()
            proc.wait(timeout=5)


class TestProcessManagerRegister:
    """Тесты метода register_process."""

    def test_register_returns_process_id(self):
        """register_process возвращает уникальный ID."""
        pm = ProcessManager()
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            pid = pm.register_process("scan-1", "nmap", proc)
            assert isinstance(pid, str)
            assert len(pid) > 0
        finally:
            pm.terminate_all()
            proc.wait(timeout=5)

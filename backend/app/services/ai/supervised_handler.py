"""SupervisedModeHandler — обработка режима с одобрением пользователя.

В Supervised Mode каждый AI-запрос требует одобрения пользователя
перед выполнением.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Callable

from app.models.ai_scan_schemas import (
    AIRequest,
    ApprovalDecision,
    ApprovalRequest,
    TestHypothesis,
)

logger = logging.getLogger(__name__)


@dataclass
class PendingApproval:
    """Ожидающий одобрения запрос."""

    request: ApprovalRequest
    event: asyncio.Event = field(default_factory=asyncio.Event)
    decision: ApprovalDecision | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class SupervisedModeHandler:
    """Обрабатывает Supervised Mode — одобрение запросов пользователем."""

    DEFAULT_TIMEOUT = 300  # 5 минут

    def __init__(
        self,
        timeout_seconds: int = DEFAULT_TIMEOUT,
        on_approval_requested: Callable[[ApprovalRequest], None] | None = None,
    ) -> None:
        """Инициализация handler.

        Args:
            timeout_seconds: таймаут ожидания одобрения.
            on_approval_requested: callback при создании запроса на одобрение.
        """
        self._timeout = timeout_seconds
        self._on_approval_requested = on_approval_requested

        # Очередь ожидающих одобрения: request_id -> PendingApproval
        self._pending: dict[str, PendingApproval] = {}

        # Статистика
        self._total_requested = 0
        self._total_approved = 0
        self._total_rejected = 0
        self._total_timeout = 0

    async def request_approval(
        self,
        scan_id: str,
        hypothesis: TestHypothesis,
        ai_request: AIRequest,
        risks: list[str] | None = None,
    ) -> bool:
        """Запрашивает одобрение пользователя для запроса.

        Args:
            scan_id: ID сканирования.
            hypothesis: гипотеза.
            ai_request: AI-запрос для одобрения.
            risks: список потенциальных рисков.

        Returns:
            True если одобрено, False если отклонено или таймаут.
        """
        approval_request = ApprovalRequest(
            request_id=ai_request.id,
            scan_id=scan_id,
            hypothesis=hypothesis,
            ai_request=ai_request,
            risks=risks or self._assess_risks(hypothesis, ai_request),
            created_at=datetime.now(UTC),
        )

        pending = PendingApproval(request=approval_request)
        self._pending[ai_request.id] = pending
        self._total_requested += 1

        logger.info(
            "Approval requested for request %s (hypothesis: %s)",
            ai_request.id,
            hypothesis.id,
        )

        # Вызываем callback если есть
        if self._on_approval_requested:
            try:
                self._on_approval_requested(approval_request)
            except Exception as e:
                logger.warning("Approval callback failed: %s", e)

        # Ожидаем решения с таймаутом
        try:
            await asyncio.wait_for(pending.event.wait(), timeout=self._timeout)
        except asyncio.TimeoutError:
            logger.warning("Approval timeout for request %s", ai_request.id)
            self._total_timeout += 1
            self._pending.pop(ai_request.id, None)
            return False

        # Получаем решение
        decision = pending.decision
        self._pending.pop(ai_request.id, None)

        if decision is None:
            return False

        if decision.approved:
            self._total_approved += 1
            logger.info("Request %s approved", ai_request.id)
            return True
        else:
            self._total_rejected += 1
            logger.info("Request %s rejected: %s", ai_request.id, decision.reason)
            return False

    def submit_decision(
        self,
        request_id: str,
        approved: bool,
        reason: str | None = None,
    ) -> bool:
        """Отправляет решение пользователя.

        Args:
            request_id: ID запроса.
            approved: одобрено или отклонено.
            reason: причина (для отклонения).

        Returns:
            True если решение принято, False если запрос не найден.
        """
        pending = self._pending.get(request_id)
        if pending is None:
            logger.warning("No pending approval for request %s", request_id)
            return False

        pending.decision = ApprovalDecision(
            request_id=request_id,
            approved=approved,
            reason=reason,
            decided_at=datetime.now(UTC),
        )
        pending.event.set()

        return True

    def get_pending_approvals(self, scan_id: str | None = None) -> list[ApprovalRequest]:
        """Возвращает список ожидающих одобрения запросов.

        Args:
            scan_id: фильтр по scan_id (опционально).

        Returns:
            Список ApprovalRequest.
        """
        approvals = [p.request for p in self._pending.values()]

        if scan_id:
            approvals = [a for a in approvals if a.scan_id == scan_id]

        return approvals

    def get_pending_count(self, scan_id: str | None = None) -> int:
        """Возвращает количество ожидающих одобрения.

        Args:
            scan_id: фильтр по scan_id (опционально).

        Returns:
            Количество pending approvals.
        """
        if scan_id:
            return sum(1 for p in self._pending.values() if p.request.scan_id == scan_id)
        return len(self._pending)

    def cancel_all(self, scan_id: str) -> int:
        """Отменяет все ожидающие одобрения для сканирования.

        Args:
            scan_id: ID сканирования.

        Returns:
            Количество отменённых запросов.
        """
        to_cancel = [
            request_id
            for request_id, pending in self._pending.items()
            if pending.request.scan_id == scan_id
        ]

        for request_id in to_cancel:
            pending = self._pending.pop(request_id, None)
            if pending:
                pending.decision = ApprovalDecision(
                    request_id=request_id,
                    approved=False,
                    reason="Scan cancelled",
                    decided_at=datetime.now(UTC),
                )
                pending.event.set()

        logger.info("Cancelled %d pending approvals for scan %s", len(to_cancel), scan_id)
        return len(to_cancel)

    def _assess_risks(
        self,
        hypothesis: TestHypothesis,
        ai_request: AIRequest,
    ) -> list[str]:
        """Оценивает потенциальные риски запроса.

        Args:
            hypothesis: гипотеза.
            ai_request: запрос.

        Returns:
            Список рисков.
        """
        risks = []

        # Риски по типу уязвимости
        vuln_type = hypothesis.vulnerability_type.lower()
        if vuln_type in ("sqli", "sql_injection"):
            risks.append("SQL injection может раскрыть данные БД")
        elif vuln_type in ("path_traversal", "lfi"):
            risks.append("Path traversal может раскрыть системные файлы")
        elif vuln_type in ("ssrf",):
            risks.append("SSRF может получить доступ к внутренним сервисам")
        elif vuln_type in ("rce", "remote_code_execution"):
            risks.append("RCE тест — высокий риск, только read-only проверка")

        # Риски по методу
        if ai_request.method in ("POST", "PUT", "PATCH"):
            risks.append(f"Метод {ai_request.method} может модифицировать данные")

        # Риски по URL
        url_lower = ai_request.url.lower()
        if "admin" in url_lower:
            risks.append("Запрос к административному разделу")
        if "api" in url_lower:
            risks.append("Запрос к API endpoint")
        if "internal" in url_lower or "localhost" in url_lower:
            risks.append("Запрос к внутреннему ресурсу")

        # Риски по body
        if ai_request.body:
            body_lower = ai_request.body.lower()
            if "select" in body_lower or "union" in body_lower:
                risks.append("SQL payload в теле запроса")
            if "../" in body_lower or "..%2f" in body_lower:
                risks.append("Path traversal payload в теле запроса")

        return risks if risks else ["Стандартный тестовый запрос"]

    def get_stats(self) -> dict:
        """Возвращает статистику."""
        return {
            "total_requested": self._total_requested,
            "total_approved": self._total_approved,
            "total_rejected": self._total_rejected,
            "total_timeout": self._total_timeout,
            "pending_count": len(self._pending),
        }


class SyncSupervisedHandler:
    """Синхронная версия SupervisedModeHandler для использования без asyncio."""

    def __init__(self, auto_approve: bool = False) -> None:
        """Инициализация.

        Args:
            auto_approve: автоматически одобрять все запросы (для тестов).
        """
        self._auto_approve = auto_approve
        self._pending: list[ApprovalRequest] = []
        self._decisions: dict[str, bool] = {}

    def request_approval(
        self,
        scan_id: str,
        hypothesis: TestHypothesis,
        ai_request: AIRequest,
        risks: list[str] | None = None,
    ) -> bool:
        """Синхронный запрос одобрения.

        В синхронном режиме либо auto_approve, либо проверяем pre-set decisions.
        """
        if self._auto_approve:
            return True

        # Проверяем pre-set decision
        if ai_request.id in self._decisions:
            return self._decisions.pop(ai_request.id)

        # Добавляем в pending для внешней обработки
        approval_request = ApprovalRequest(
            request_id=ai_request.id,
            scan_id=scan_id,
            hypothesis=hypothesis,
            ai_request=ai_request,
            risks=risks or [],
            created_at=datetime.now(UTC),
        )
        self._pending.append(approval_request)

        # В синхронном режиме без auto_approve — отклоняем
        return False

    def pre_approve(self, request_id: str) -> None:
        """Предварительно одобряет запрос."""
        self._decisions[request_id] = True

    def pre_reject(self, request_id: str) -> None:
        """Предварительно отклоняет запрос."""
        self._decisions[request_id] = False

    def get_pending(self) -> list[ApprovalRequest]:
        """Возвращает pending запросы."""
        return list(self._pending)

    def clear_pending(self) -> None:
        """Очищает pending запросы."""
        self._pending.clear()

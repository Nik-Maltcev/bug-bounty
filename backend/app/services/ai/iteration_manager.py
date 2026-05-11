"""IterationManager — управление итеративным углублением тестирования.

Отслеживает глубину итераций, количество запросов и строит
дерево исследования для отчёта.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class TestNode:
    """Узел в дереве исследования."""

    hypothesis_id: str
    parent_id: str | None
    iteration: int
    status: str  # pending, executed, confirmed, refuted, blocked
    vulnerability_type: str
    description: str
    children: list[str] = field(default_factory=list)


@dataclass
class IterationState:
    """Состояние итеративного тестирования."""

    current_depth: int = 0
    total_requests: int = 0
    total_hypotheses: int = 0
    confirmed_count: int = 0
    blocked_count: int = 0
    started_at: datetime | None = None
    last_activity: datetime | None = None


class IterationManager:
    """Управляет итеративным углублением тестирования."""

    MAX_DEPTH = 3       # Максимальная глубина итераций
    MAX_REQUESTS = 50   # Максимальное количество запросов

    def __init__(
        self,
        max_depth: int = MAX_DEPTH,
        max_requests: int = MAX_REQUESTS,
    ) -> None:
        """Инициализация менеджера.

        Args:
            max_depth: максимальная глубина итераций.
            max_requests: максимальное количество запросов.
        """
        self._max_depth = max_depth
        self._max_requests = max_requests
        self._state = IterationState(started_at=datetime.now(UTC))

        # Дерево исследования: hypothesis_id -> TestNode
        self._tree: dict[str, TestNode] = {}

        # Маппинг child -> parent
        self._parent_map: dict[str, str] = {}

    @property
    def current_depth(self) -> int:
        """Текущая глубина итерации."""
        return self._state.current_depth

    @property
    def total_requests(self) -> int:
        """Общее количество выполненных запросов."""
        return self._state.total_requests

    @property
    def total_hypotheses(self) -> int:
        """Общее количество гипотез."""
        return self._state.total_hypotheses

    @property
    def confirmed_count(self) -> int:
        """Количество подтверждённых уязвимостей."""
        return self._state.confirmed_count

    def can_continue(self) -> bool:
        """Проверяет, можно ли продолжать тестирование.

        Returns:
            True если не достигнуты лимиты.
        """
        if self._state.current_depth >= self._max_depth:
            logger.info("Iteration limit reached: depth=%d", self._state.current_depth)
            return False

        if self._state.total_requests >= self._max_requests:
            logger.info("Request limit reached: requests=%d", self._state.total_requests)
            return False

        return True

    def can_add_request(self) -> bool:
        """Проверяет, можно ли добавить ещё один запрос.

        Returns:
            True если лимит запросов не достигнут.
        """
        return self._state.total_requests < self._max_requests

    def start_iteration(self, depth: int) -> None:
        """Начинает новую итерацию.

        Args:
            depth: глубина итерации (0, 1, 2).
        """
        self._state.current_depth = depth
        self._state.last_activity = datetime.now(UTC)
        logger.info("Starting iteration %d", depth)

    def record_hypothesis(
        self,
        hypothesis_id: str,
        parent_id: str | None,
        vulnerability_type: str,
        description: str,
    ) -> None:
        """Записывает гипотезу в дерево исследования.

        Args:
            hypothesis_id: ID гипотезы.
            parent_id: ID родительской гипотезы (для follow-up).
            vulnerability_type: тип уязвимости.
            description: описание гипотезы.
        """
        node = TestNode(
            hypothesis_id=hypothesis_id,
            parent_id=parent_id,
            iteration=self._state.current_depth,
            status="pending",
            vulnerability_type=vulnerability_type,
            description=description,
        )
        self._tree[hypothesis_id] = node
        self._state.total_hypotheses += 1

        if parent_id:
            self._parent_map[hypothesis_id] = parent_id
            # Добавляем в children родителя
            if parent_id in self._tree:
                self._tree[parent_id].children.append(hypothesis_id)

        self._state.last_activity = datetime.now(UTC)

    def record_request(self, hypothesis_id: str) -> None:
        """Записывает выполненный запрос.

        Args:
            hypothesis_id: ID гипотезы, для которой выполнен запрос.
        """
        self._state.total_requests += 1
        self._state.last_activity = datetime.now(UTC)

        if hypothesis_id in self._tree:
            self._tree[hypothesis_id].status = "executed"

    def record_result(
        self,
        hypothesis_id: str,
        confirmed: bool,
        blocked: bool = False,
    ) -> None:
        """Записывает результат проверки гипотезы.

        Args:
            hypothesis_id: ID гипотезы.
            confirmed: подтверждена ли уязвимость.
            blocked: заблокирован ли запрос compliance.
        """
        if hypothesis_id in self._tree:
            if blocked:
                self._tree[hypothesis_id].status = "blocked"
                self._state.blocked_count += 1
            elif confirmed:
                self._tree[hypothesis_id].status = "confirmed"
                self._state.confirmed_count += 1
            else:
                self._tree[hypothesis_id].status = "refuted"

        self._state.last_activity = datetime.now(UTC)

    def get_parent(self, hypothesis_id: str) -> str | None:
        """Возвращает ID родительской гипотезы.

        Args:
            hypothesis_id: ID гипотезы.

        Returns:
            ID родителя или None.
        """
        return self._parent_map.get(hypothesis_id)

    def get_depth(self, hypothesis_id: str) -> int:
        """Возвращает глубину гипотезы в дереве.

        Args:
            hypothesis_id: ID гипотезы.

        Returns:
            Глубина (0 = корневая).
        """
        depth = 0
        current = hypothesis_id
        while current in self._parent_map:
            current = self._parent_map[current]
            depth += 1
        return depth

    def get_tree(self) -> dict:
        """Возвращает дерево исследования для отчёта.

        Returns:
            Структурированное дерево.
        """
        # Находим корневые узлы (без родителя)
        roots = [
            node for node in self._tree.values()
            if node.parent_id is None
        ]

        def build_subtree(node: TestNode) -> dict:
            return {
                "hypothesis_id": node.hypothesis_id,
                "iteration": node.iteration,
                "status": node.status,
                "vulnerability_type": node.vulnerability_type,
                "description": node.description[:100],
                "children": [
                    build_subtree(self._tree[child_id])
                    for child_id in node.children
                    if child_id in self._tree
                ],
            }

        return {
            "roots": [build_subtree(root) for root in roots],
            "stats": {
                "total_hypotheses": self._state.total_hypotheses,
                "total_requests": self._state.total_requests,
                "confirmed": self._state.confirmed_count,
                "blocked": self._state.blocked_count,
                "max_depth_reached": self._state.current_depth,
            },
        }

    def get_state(self) -> IterationState:
        """Возвращает текущее состояние."""
        return self._state

    def get_stats(self) -> dict:
        """Возвращает статистику для API."""
        return {
            "current_depth": self._state.current_depth,
            "max_depth": self._max_depth,
            "total_requests": self._state.total_requests,
            "max_requests": self._max_requests,
            "total_hypotheses": self._state.total_hypotheses,
            "confirmed_count": self._state.confirmed_count,
            "blocked_count": self._state.blocked_count,
            "can_continue": self.can_continue(),
        }

    def reset(self) -> None:
        """Сбрасывает состояние менеджера."""
        self._state = IterationState(started_at=datetime.now(UTC))
        self._tree.clear()
        self._parent_map.clear()

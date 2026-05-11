"""Тесты для IterationManager — управление итеративным тестированием."""

import pytest

from app.services.ai.iteration_manager import IterationManager, IterationState, TestNode


class TestIterationManagerInit:
    """Тесты инициализации IterationManager."""

    def test_default_limits(self):
        """Дефолтные лимиты: 3 итерации, 50 запросов."""
        manager = IterationManager()
        assert manager._max_depth == 3
        assert manager._max_requests == 50

    def test_custom_limits(self):
        """Кастомные лимиты."""
        manager = IterationManager(max_depth=5, max_requests=100)
        assert manager._max_depth == 5
        assert manager._max_requests == 100

    def test_initial_state(self):
        """Начальное состояние."""
        manager = IterationManager()
        assert manager.current_depth == 0
        assert manager.total_requests == 0
        assert manager.total_hypotheses == 0
        assert manager.confirmed_count == 0


class TestCanContinue:
    """Тесты can_continue."""

    def test_can_continue_initially(self):
        """Изначально можно продолжать."""
        manager = IterationManager(max_depth=3, max_requests=50)
        assert manager.can_continue() is True

    def test_cannot_continue_at_max_depth(self):
        """Нельзя продолжать при достижении max_depth."""
        manager = IterationManager(max_depth=2, max_requests=50)

        manager.start_iteration(0)
        assert manager.can_continue() is True

        manager.start_iteration(1)
        assert manager.can_continue() is True

        manager.start_iteration(2)
        assert manager.can_continue() is False

    def test_cannot_continue_at_max_requests(self):
        """Нельзя продолжать при достижении max_requests."""
        manager = IterationManager(max_depth=10, max_requests=3)

        manager.record_request("h1")
        assert manager.can_continue() is True

        manager.record_request("h2")
        assert manager.can_continue() is True

        manager.record_request("h3")
        assert manager.can_continue() is False


class TestCanAddRequest:
    """Тесты can_add_request."""

    def test_can_add_request_initially(self):
        """Изначально можно добавлять запросы."""
        manager = IterationManager(max_requests=5)
        assert manager.can_add_request() is True

    def test_cannot_add_request_at_limit(self):
        """Нельзя добавлять при достижении лимита."""
        manager = IterationManager(max_requests=2)

        manager.record_request("h1")
        assert manager.can_add_request() is True

        manager.record_request("h2")
        assert manager.can_add_request() is False


class TestStartIteration:
    """Тесты start_iteration."""

    def test_start_iteration_updates_depth(self):
        """start_iteration обновляет текущую глубину."""
        manager = IterationManager()

        manager.start_iteration(0)
        assert manager.current_depth == 0

        manager.start_iteration(1)
        assert manager.current_depth == 1

        manager.start_iteration(2)
        assert manager.current_depth == 2

    def test_start_iteration_updates_last_activity(self):
        """start_iteration обновляет last_activity."""
        manager = IterationManager()
        initial_activity = manager._state.last_activity

        manager.start_iteration(0)
        assert manager._state.last_activity is not None
        assert manager._state.last_activity != initial_activity


class TestRecordHypothesis:
    """Тесты record_hypothesis."""

    def test_record_hypothesis_increments_counter(self):
        """record_hypothesis увеличивает счётчик гипотез."""
        manager = IterationManager()
        assert manager.total_hypotheses == 0

        manager.record_hypothesis("h1", None, "sqli", "SQL injection test")
        assert manager.total_hypotheses == 1

        manager.record_hypothesis("h2", None, "xss", "XSS test")
        assert manager.total_hypotheses == 2

    def test_record_hypothesis_adds_to_tree(self):
        """record_hypothesis добавляет узел в дерево."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "SQL injection test")

        assert "h1" in manager._tree
        node = manager._tree["h1"]
        assert node.hypothesis_id == "h1"
        assert node.parent_id is None
        assert node.vulnerability_type == "sqli"
        assert node.status == "pending"

    def test_record_hypothesis_with_parent(self):
        """record_hypothesis с родителем."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Initial test")
        manager.record_hypothesis("h2", "h1", "sqli", "Follow-up test")

        assert manager._parent_map["h2"] == "h1"
        assert "h2" in manager._tree["h1"].children


class TestRecordRequest:
    """Тесты record_request."""

    def test_record_request_increments_counter(self):
        """record_request увеличивает счётчик запросов."""
        manager = IterationManager()
        assert manager.total_requests == 0

        manager.record_request("h1")
        assert manager.total_requests == 1

        manager.record_request("h2")
        assert manager.total_requests == 2

    def test_record_request_updates_node_status(self):
        """record_request обновляет статус узла на 'executed'."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Test")
        assert manager._tree["h1"].status == "pending"

        manager.record_request("h1")
        assert manager._tree["h1"].status == "executed"


class TestRecordResult:
    """Тесты record_result."""

    def test_record_result_confirmed(self):
        """record_result с confirmed=True."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Test")
        manager.record_result("h1", confirmed=True)

        assert manager._tree["h1"].status == "confirmed"
        assert manager.confirmed_count == 1

    def test_record_result_refuted(self):
        """record_result с confirmed=False."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Test")
        manager.record_result("h1", confirmed=False)

        assert manager._tree["h1"].status == "refuted"
        assert manager.confirmed_count == 0

    def test_record_result_blocked(self):
        """record_result с blocked=True."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Test")
        manager.record_result("h1", confirmed=False, blocked=True)

        assert manager._tree["h1"].status == "blocked"
        assert manager._state.blocked_count == 1


class TestGetParent:
    """Тесты get_parent."""

    def test_get_parent_root_node(self):
        """get_parent для корневого узла возвращает None."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Root test")
        assert manager.get_parent("h1") is None

    def test_get_parent_child_node(self):
        """get_parent для дочернего узла возвращает ID родителя."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Root")
        manager.record_hypothesis("h2", "h1", "sqli", "Child")

        assert manager.get_parent("h2") == "h1"


class TestGetDepth:
    """Тесты get_depth."""

    def test_get_depth_root(self):
        """get_depth для корневого узла = 0."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Root")
        assert manager.get_depth("h1") == 0

    def test_get_depth_nested(self):
        """get_depth для вложенных узлов."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Level 0")
        manager.record_hypothesis("h2", "h1", "sqli", "Level 1")
        manager.record_hypothesis("h3", "h2", "sqli", "Level 2")

        assert manager.get_depth("h1") == 0
        assert manager.get_depth("h2") == 1
        assert manager.get_depth("h3") == 2


class TestGetTree:
    """Тесты get_tree."""

    def test_get_tree_empty(self):
        """get_tree для пустого дерева."""
        manager = IterationManager()
        tree = manager.get_tree()

        assert tree["roots"] == []
        assert tree["stats"]["total_hypotheses"] == 0

    def test_get_tree_single_root(self):
        """get_tree с одним корневым узлом."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Root test")
        tree = manager.get_tree()

        assert len(tree["roots"]) == 1
        assert tree["roots"][0]["hypothesis_id"] == "h1"
        assert tree["roots"][0]["children"] == []

    def test_get_tree_with_children(self):
        """get_tree с дочерними узлами."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Root")
        manager.record_hypothesis("h2", "h1", "sqli", "Child 1")
        manager.record_hypothesis("h3", "h1", "sqli", "Child 2")

        tree = manager.get_tree()

        assert len(tree["roots"]) == 1
        root = tree["roots"][0]
        assert len(root["children"]) == 2

    def test_get_tree_stats(self):
        """get_tree содержит корректную статистику."""
        manager = IterationManager()

        manager.record_hypothesis("h1", None, "sqli", "Test 1")
        manager.record_hypothesis("h2", None, "xss", "Test 2")
        manager.record_request("h1")
        manager.record_request("h2")
        manager.record_result("h1", confirmed=True)
        manager.record_result("h2", confirmed=False, blocked=True)

        tree = manager.get_tree()
        stats = tree["stats"]

        assert stats["total_hypotheses"] == 2
        assert stats["total_requests"] == 2
        assert stats["confirmed"] == 1
        assert stats["blocked"] == 1


class TestGetStats:
    """Тесты get_stats."""

    def test_get_stats_initial(self):
        """get_stats для начального состояния."""
        manager = IterationManager(max_depth=3, max_requests=50)
        stats = manager.get_stats()

        assert stats["current_depth"] == 0
        assert stats["max_depth"] == 3
        assert stats["total_requests"] == 0
        assert stats["max_requests"] == 50
        assert stats["can_continue"] is True

    def test_get_stats_after_operations(self):
        """get_stats после операций."""
        manager = IterationManager(max_depth=2, max_requests=10)

        manager.start_iteration(1)
        manager.record_hypothesis("h1", None, "sqli", "Test")
        manager.record_request("h1")
        manager.record_result("h1", confirmed=True)

        stats = manager.get_stats()

        assert stats["current_depth"] == 1
        assert stats["total_requests"] == 1
        assert stats["total_hypotheses"] == 1
        assert stats["confirmed_count"] == 1


class TestReset:
    """Тесты reset."""

    def test_reset_clears_state(self):
        """reset очищает состояние."""
        manager = IterationManager()

        manager.start_iteration(2)
        manager.record_hypothesis("h1", None, "sqli", "Test")
        manager.record_request("h1")
        manager.record_result("h1", confirmed=True)

        manager.reset()

        assert manager.current_depth == 0
        assert manager.total_requests == 0
        assert manager.total_hypotheses == 0
        assert manager.confirmed_count == 0
        assert len(manager._tree) == 0
        assert len(manager._parent_map) == 0


class TestComplexScenarios:
    """Комплексные сценарии."""

    def test_full_iteration_cycle(self):
        """Полный цикл итераций."""
        manager = IterationManager(max_depth=3, max_requests=10)

        # Итерация 0
        manager.start_iteration(0)
        manager.record_hypothesis("h1", None, "sqli", "Initial SQLi test")
        manager.record_request("h1")
        manager.record_result("h1", confirmed=True)

        # Итерация 1 (follow-up)
        manager.start_iteration(1)
        manager.record_hypothesis("h2", "h1", "sqli", "Deep SQLi test")
        manager.record_request("h2")
        manager.record_result("h2", confirmed=False)

        # Итерация 2
        manager.start_iteration(2)
        manager.record_hypothesis("h3", None, "xss", "XSS test")
        manager.record_request("h3")
        manager.record_result("h3", confirmed=False, blocked=True)

        # Проверяем финальное состояние
        assert manager.total_hypotheses == 3
        assert manager.total_requests == 3
        assert manager.confirmed_count == 1
        assert manager._state.blocked_count == 1

        # Итерация 3 — достигаем max_depth
        manager.start_iteration(3)
        assert manager.can_continue() is False  # достигли max_depth

        # Проверяем дерево
        tree = manager.get_tree()
        assert len(tree["roots"]) == 2  # h1 и h3 — корневые
        assert tree["stats"]["confirmed"] == 1

    def test_request_limit_stops_iteration(self):
        """Лимит запросов останавливает итерации."""
        manager = IterationManager(max_depth=10, max_requests=3)

        for i in range(5):
            if not manager.can_add_request():
                break
            manager.record_hypothesis(f"h{i}", None, "test", f"Test {i}")
            manager.record_request(f"h{i}")

        assert manager.total_requests == 3
        assert manager.can_continue() is False

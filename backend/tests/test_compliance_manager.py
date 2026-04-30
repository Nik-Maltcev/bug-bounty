"""Тесты для ComplianceManager — валидация действий и области действия."""

import uuid

import pytest

from app.models.schemas import Asset, AssetType, ProgramRule
from app.services.compliance_manager import AgentAction, ComplianceManager


@pytest.fixture
def manager() -> ComplianceManager:
    return ComplianceManager()


def _rule(description: str, is_allowed: bool, category: str = "general") -> ProgramRule:
    """Хелпер для создания правила."""
    return ProgramRule(
        id=str(uuid.uuid4()),
        description=description,
        is_allowed=is_allowed,
        category=category,
    )


def _asset(target: str, in_scope: bool = True) -> Asset:
    """Хелпер для создания актива."""
    return Asset(
        id=str(uuid.uuid4()),
        name=f"Asset {target}",
        asset_type=AssetType.WEB_APPLICATION,
        target=target,
        in_scope=in_scope,
    )


# --- validate_action ---


class TestValidateAction:
    """Тесты validate_action."""

    def test_allowed_when_no_forbidden_rules(self, manager: ComplianceManager):
        """Действие разрешено, если нет запрещающих правил."""
        action = AgentAction(
            action_type="scan",
            target="https://example.com",
            description="port scanning",
        )
        rules = [
            _rule("Port scanning is allowed", is_allowed=True, category="testing_method"),
        ]
        result = manager.validate_action(action, rules)
        assert result.action_allowed is True
        assert result.rule_reference is None

    def test_allowed_with_empty_rules(self, manager: ComplianceManager):
        """Действие разрешено при пустом списке правил."""
        action = AgentAction(
            action_type="scan",
            target="https://example.com",
            description="basic web scan",
        )
        result = manager.validate_action(action, rules=[])
        assert result.action_allowed is True

    def test_blocked_when_matching_forbidden_rule(self, manager: ComplianceManager):
        """Действие блокируется при совпадении с запрещающим правилом."""
        action = AgentAction(
            action_type="dos",
            target="https://example.com",
            description="denial of service attack",
        )
        forbidden_rule = _rule(
            "DoS and denial of service attacks are forbidden",
            is_allowed=False,
            category="testing_method",
        )
        result = manager.validate_action(action, [forbidden_rule])
        assert result.action_allowed is False
        assert result.rule_reference == forbidden_rule.id
        assert "правило" in result.reason.lower() or "rule" in result.reason.lower() or "правил" in result.reason.lower()

    def test_blocked_by_description_keyword_match(self, manager: ComplianceManager):
        """Блокировка по совпадению ключевых слов в описании."""
        action = AgentAction(
            action_type="test",
            target="https://example.com",
            description="brute force login attempt",
        )
        forbidden_rule = _rule(
            "Brute force attacks are not permitted",
            is_allowed=False,
            category="testing_method",
        )
        result = manager.validate_action(action, [forbidden_rule])
        assert result.action_allowed is False

    def test_multiple_rules_mixed_allowed_forbidden(self, manager: ComplianceManager):
        """Несколько правил: разрешённые и запрещённые. Блокировка при совпадении с запрещённым."""
        action = AgentAction(
            action_type="scan",
            target="https://example.com",
            description="fuzzing the API endpoints",
        )
        rules = [
            _rule("Port scanning is allowed", is_allowed=True),
            _rule("SQL injection testing is allowed", is_allowed=True),
            _rule("Fuzzing is forbidden on production", is_allowed=False),
        ]
        result = manager.validate_action(action, rules)
        assert result.action_allowed is False
        assert result.rule_reference == rules[2].id

    def test_allowed_when_forbidden_rule_does_not_match(self, manager: ComplianceManager):
        """Действие разрешено, если запрещающее правило не совпадает."""
        action = AgentAction(
            action_type="scan",
            target="https://example.com",
            description="basic port scan",
        )
        rules = [
            _rule("DoS attacks are forbidden", is_allowed=False),
            _rule("Brute force is forbidden", is_allowed=False),
        ]
        result = manager.validate_action(action, rules)
        assert result.action_allowed is True


# --- validate_target ---


class TestValidateTarget:
    """Тесты validate_target."""

    def test_target_in_scope(self, manager: ComplianceManager):
        """Цель в scope возвращает True."""
        scope = [
            _asset("https://app.example.com", in_scope=True),
            _asset("https://api.example.com", in_scope=True),
        ]
        assert manager.validate_target("https://app.example.com", scope) is True

    def test_target_out_of_scope(self, manager: ComplianceManager):
        """Цель вне scope возвращает False."""
        scope = [
            _asset("https://app.example.com", in_scope=True),
        ]
        assert manager.validate_target("https://other.example.com", scope) is False

    def test_target_marked_out_of_scope(self, manager: ComplianceManager):
        """Актив с in_scope=False возвращает False."""
        scope = [
            _asset("https://admin.example.com", in_scope=False),
        ]
        assert manager.validate_target("https://admin.example.com", scope) is False

    def test_empty_scope(self, manager: ComplianceManager):
        """Пустой scope — всегда False."""
        assert manager.validate_target("https://example.com", []) is False

    def test_multiple_assets_mixed_scope(self, manager: ComplianceManager):
        """Несколько активов: один in_scope, другой нет."""
        scope = [
            _asset("https://app.example.com", in_scope=True),
            _asset("https://admin.example.com", in_scope=False),
        ]
        assert manager.validate_target("https://app.example.com", scope) is True
        assert manager.validate_target("https://admin.example.com", scope) is False


# --- DB-backed tests: get_compliance_summary, load_program_rules, load_program_scope ---

from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.database import (
    AuditLog,
    Base,
    Program,
)
from app.models.database import Asset as AssetDB
from app.models.database import ProgramRule as ProgramRuleDB


@pytest.fixture()
def db_session():
    """In-memory SQLite для тестов."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _seed_program(db: Session, program_id: str, name: str = "Test Program") -> Program:
    """Создаёт программу в БД."""
    p = Program(
        id=program_id,
        name=name,
        platform="custom",
        disclosure_requirements="",
        raw_text="",
    )
    db.add(p)
    db.commit()
    return p


def _seed_audit_log(
    db: Session,
    program_id: str,
    result: str,
    details: str = "",
    action_type: str = "scan",
) -> AuditLog:
    """Создаёт запись аудита в БД."""
    entry = AuditLog(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        action_type=action_type,
        target_asset="https://example.com",
        result=result,
        program_id=program_id,
        rule_reference="",
        details=details,
    )
    db.add(entry)
    db.commit()
    return entry


def _seed_db_rule(
    db: Session,
    program_id: str,
    description: str,
    is_allowed: bool,
    category: str = "testing_method",
) -> ProgramRuleDB:
    """Создаёт правило программы в БД."""
    rule = ProgramRuleDB(
        id=str(uuid.uuid4()),
        program_id=program_id,
        description=description,
        is_allowed=is_allowed,
        category=category,
    )
    db.add(rule)
    db.commit()
    return rule


def _seed_db_asset(
    db: Session,
    program_id: str,
    target: str,
    in_scope: bool = True,
    asset_type: str = "web_application",
) -> AssetDB:
    """Создаёт актив программы в БД."""
    asset = AssetDB(
        id=str(uuid.uuid4()),
        program_id=program_id,
        name=f"Asset {target}",
        asset_type=asset_type,
        target=target,
        in_scope=in_scope,
        notes="",
    )
    db.add(asset)
    db.commit()
    return asset


class TestGetComplianceSummary:
    """Тесты get_compliance_summary."""

    def test_empty_audit_log(self, manager: ComplianceManager, db_session: Session):
        """Пустой журнал — все счётчики нулевые."""
        _seed_program(db_session, "prog-1")
        summary = manager.get_compliance_summary("prog-1", db_session)
        assert summary.program_id == "prog-1"
        assert summary.total_actions == 0
        assert summary.allowed_actions == 0
        assert summary.blocked_actions == 0
        assert summary.blocked_reasons == []

    def test_counts_allowed_and_blocked(self, manager: ComplianceManager, db_session: Session):
        """Корректный подсчёт allowed и blocked действий."""
        _seed_program(db_session, "prog-1")
        _seed_audit_log(db_session, "prog-1", "allowed")
        _seed_audit_log(db_session, "prog-1", "allowed")
        _seed_audit_log(db_session, "prog-1", "blocked", details="DoS запрещён")
        _seed_audit_log(db_session, "prog-1", "blocked", details="Brute force запрещён")
        _seed_audit_log(db_session, "prog-1", "blocked", details="DoS запрещён")

        summary = manager.get_compliance_summary("prog-1", db_session)
        assert summary.total_actions == 5
        assert summary.allowed_actions == 2
        assert summary.blocked_actions == 3

    def test_blocked_reasons_grouped(self, manager: ComplianceManager, db_session: Session):
        """Причины блокировок группируются с подсчётом."""
        _seed_program(db_session, "prog-1")
        _seed_audit_log(db_session, "prog-1", "blocked", details="DoS запрещён")
        _seed_audit_log(db_session, "prog-1", "blocked", details="DoS запрещён")
        _seed_audit_log(db_session, "prog-1", "blocked", details="Brute force запрещён")

        summary = manager.get_compliance_summary("prog-1", db_session)
        reasons = {r["reason"]: r["count"] for r in summary.blocked_reasons}
        assert reasons["DoS запрещён"] == 2
        assert reasons["Brute force запрещён"] == 1

    def test_summary_scoped_to_program(self, manager: ComplianceManager, db_session: Session):
        """Сводка учитывает только записи указанной программы."""
        _seed_program(db_session, "prog-1")
        _seed_program(db_session, "prog-2")
        _seed_audit_log(db_session, "prog-1", "allowed")
        _seed_audit_log(db_session, "prog-1", "blocked", details="reason A")
        _seed_audit_log(db_session, "prog-2", "allowed")
        _seed_audit_log(db_session, "prog-2", "allowed")
        _seed_audit_log(db_session, "prog-2", "allowed")

        s1 = manager.get_compliance_summary("prog-1", db_session)
        s2 = manager.get_compliance_summary("prog-2", db_session)
        assert s1.total_actions == 2
        assert s1.blocked_actions == 1
        assert s2.total_actions == 3
        assert s2.blocked_actions == 0


class TestLoadProgramRules:
    """Тесты load_program_rules."""

    def test_returns_rules_for_program(self, manager: ComplianceManager, db_session: Session):
        """Возвращает правила указанной программы."""
        _seed_program(db_session, "prog-1")
        _seed_db_rule(db_session, "prog-1", "No DoS attacks", is_allowed=False)
        _seed_db_rule(db_session, "prog-1", "Port scanning allowed", is_allowed=True)

        rules = manager.load_program_rules("prog-1", db_session)
        assert len(rules) == 2
        descriptions = {r.description for r in rules}
        assert "No DoS attacks" in descriptions
        assert "Port scanning allowed" in descriptions

    def test_empty_when_no_rules(self, manager: ComplianceManager, db_session: Session):
        """Пустой список, если у программы нет правил."""
        _seed_program(db_session, "prog-1")
        rules = manager.load_program_rules("prog-1", db_session)
        assert rules == []

    def test_isolation_rules_from_other_program(self, manager: ComplianceManager, db_session: Session):
        """Правила программы A не попадают в программу B."""
        _seed_program(db_session, "prog-A")
        _seed_program(db_session, "prog-B")
        _seed_db_rule(db_session, "prog-A", "Rule for A only", is_allowed=False)
        _seed_db_rule(db_session, "prog-B", "Rule for B only", is_allowed=True)

        rules_a = manager.load_program_rules("prog-A", db_session)
        rules_b = manager.load_program_rules("prog-B", db_session)

        assert len(rules_a) == 1
        assert rules_a[0].description == "Rule for A only"
        assert len(rules_b) == 1
        assert rules_b[0].description == "Rule for B only"

    def test_returns_pydantic_models(self, manager: ComplianceManager, db_session: Session):
        """Возвращает Pydantic ProgramRule, а не ORM-объекты."""
        _seed_program(db_session, "prog-1")
        _seed_db_rule(db_session, "prog-1", "Test rule", is_allowed=True, category="scope")

        rules = manager.load_program_rules("prog-1", db_session)
        assert len(rules) == 1
        rule = rules[0]
        assert isinstance(rule, ProgramRule)
        assert rule.description == "Test rule"
        assert rule.is_allowed is True
        assert rule.category == "scope"


class TestLoadProgramScope:
    """Тесты load_program_scope."""

    def test_returns_assets_for_program(self, manager: ComplianceManager, db_session: Session):
        """Возвращает активы указанной программы."""
        _seed_program(db_session, "prog-1")
        _seed_db_asset(db_session, "prog-1", "https://app.example.com")
        _seed_db_asset(db_session, "prog-1", "https://api.example.com", in_scope=False)

        assets = manager.load_program_scope("prog-1", db_session)
        assert len(assets) == 2
        targets = {a.target for a in assets}
        assert "https://app.example.com" in targets
        assert "https://api.example.com" in targets

    def test_empty_when_no_assets(self, manager: ComplianceManager, db_session: Session):
        """Пустой список, если у программы нет активов."""
        _seed_program(db_session, "prog-1")
        assets = manager.load_program_scope("prog-1", db_session)
        assert assets == []

    def test_isolation_assets_from_other_program(self, manager: ComplianceManager, db_session: Session):
        """Активы программы A не попадают в программу B."""
        _seed_program(db_session, "prog-A")
        _seed_program(db_session, "prog-B")
        _seed_db_asset(db_session, "prog-A", "https://a.example.com")
        _seed_db_asset(db_session, "prog-B", "https://b.example.com")

        assets_a = manager.load_program_scope("prog-A", db_session)
        assets_b = manager.load_program_scope("prog-B", db_session)

        assert len(assets_a) == 1
        assert assets_a[0].target == "https://a.example.com"
        assert len(assets_b) == 1
        assert assets_b[0].target == "https://b.example.com"

    def test_returns_pydantic_models(self, manager: ComplianceManager, db_session: Session):
        """Возвращает Pydantic Asset, а не ORM-объекты."""
        _seed_program(db_session, "prog-1")
        _seed_db_asset(db_session, "prog-1", "https://app.example.com", asset_type="web_application")

        assets = manager.load_program_scope("prog-1", db_session)
        assert len(assets) == 1
        asset = assets[0]
        assert isinstance(asset, Asset)
        assert asset.target == "https://app.example.com"
        assert asset.asset_type == AssetType.WEB_APPLICATION


class TestProgramIsolation:
    """Тест изоляции: правила и активы программы A не влияют на программу B."""

    def test_full_isolation_rules_and_scope(self, manager: ComplianceManager, db_session: Session):
        """Полная изоляция: при переключении программы загружаются только её правила и активы."""
        _seed_program(db_session, "prog-A")
        _seed_program(db_session, "prog-B")

        # Правила и активы для A
        _seed_db_rule(db_session, "prog-A", "DoS forbidden for A", is_allowed=False)
        _seed_db_rule(db_session, "prog-A", "Scanning allowed for A", is_allowed=True)
        _seed_db_asset(db_session, "prog-A", "https://a1.example.com")
        _seed_db_asset(db_session, "prog-A", "https://a2.example.com")

        # Правила и активы для B
        _seed_db_rule(db_session, "prog-B", "Brute force forbidden for B", is_allowed=False)
        _seed_db_asset(db_session, "prog-B", "https://b1.example.com")

        # Загружаем для A
        rules_a = manager.load_program_rules("prog-A", db_session)
        scope_a = manager.load_program_scope("prog-A", db_session)
        assert len(rules_a) == 2
        assert len(scope_a) == 2
        assert all("for A" in r.description for r in rules_a)
        assert all("a" in a.target for a in scope_a)

        # Переключаемся на B
        rules_b = manager.load_program_rules("prog-B", db_session)
        scope_b = manager.load_program_scope("prog-B", db_session)
        assert len(rules_b) == 1
        assert len(scope_b) == 1
        assert rules_b[0].description == "Brute force forbidden for B"
        assert scope_b[0].target == "https://b1.example.com"

        # Правила A не содержат правил B и наоборот
        a_descs = {r.description for r in rules_a}
        b_descs = {r.description for r in rules_b}
        assert a_descs.isdisjoint(b_descs)

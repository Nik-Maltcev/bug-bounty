"""Менеджер контроля соответствия правилам программы bug bounty.

Проверяет действия агента на соответствие правилам программы,
валидирует область действия (scope) и блокирует запрещённые действия.
"""

import logging

from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.database import AuditLog
from app.models.database import Asset as AssetDB
from app.models.database import ProgramRule as ProgramRuleDB
from app.models.schemas import (
    Asset,
    AssetType,
    ComplianceResult,
    ComplianceSummary,
    ProgramRule,
)

logger = logging.getLogger(__name__)


class AgentAction(BaseModel):
    """Планируемое действие агента."""

    action_type: str
    target: str
    description: str


class ComplianceManager:
    """Менеджер контроля соответствия правилам программы."""

    def validate_action(
        self, action: AgentAction, rules: list[ProgramRule]
    ) -> ComplianceResult:
        """Проверяет действие на соответствие правилам.

        Для каждого запрещающего правила (is_allowed=False) проверяет,
        совпадают ли ключевые слова действия с описанием правила.
        Если совпадение найдено — действие блокируется.

        Args:
            action: планируемое действие агента.
            rules: правила текущей программы.

        Returns:
            ComplianceResult с решением (allowed/blocked) и причиной.
        """
        action_keywords = self._extract_keywords(
            f"{action.action_type} {action.description}"
        )

        for rule in rules:
            if rule.is_allowed:
                continue

            rule_keywords = self._extract_keywords(rule.description)
            if action_keywords & rule_keywords:
                logger.warning(
                    "Action BLOCKED: type=%s target=%s rule=%s",
                    action.action_type,
                    action.target,
                    rule.id,
                )
                return ComplianceResult(
                    action_allowed=False,
                    reason=f"Действие нарушает правило: {rule.description}",
                    rule_reference=rule.id,
                )

        return ComplianceResult(
            action_allowed=True,
            reason="Действие разрешено: не нарушает запрещающих правил",
            rule_reference=None,
        )

    def validate_target(self, target: str, scope: list[Asset]) -> bool:
        """Проверяет, находится ли цель в разрешённой области действия.

        Args:
            target: идентификатор актива (URL, адрес контракта и т.д.).
            scope: список активов программы.

        Returns:
            True если актив в scope (in_scope=True), False иначе.
        """
        for asset in scope:
            if asset.target == target and asset.in_scope:
                return True
        return False

    def get_compliance_summary(
        self, program_id: str, db: Session
    ) -> ComplianceSummary:
        """Возвращает сводку по соблюдению правил программы.

        Подсчитывает общее количество действий, разрешённых и заблокированных,
        а также группирует причины блокировок.

        Args:
            program_id: идентификатор программы.
            db: сессия SQLAlchemy.

        Returns:
            ComplianceSummary со статистикой по действиям.
        """
        total = db.query(func.count(AuditLog.id)).filter(
            AuditLog.program_id == program_id
        ).scalar() or 0

        allowed = db.query(func.count(AuditLog.id)).filter(
            AuditLog.program_id == program_id,
            AuditLog.result == "allowed",
        ).scalar() or 0

        blocked = db.query(func.count(AuditLog.id)).filter(
            AuditLog.program_id == program_id,
            AuditLog.result == "blocked",
        ).scalar() or 0

        # Group blocked actions by details (reason)
        blocked_rows = (
            db.query(AuditLog.details, func.count(AuditLog.id))
            .filter(
                AuditLog.program_id == program_id,
                AuditLog.result == "blocked",
            )
            .group_by(AuditLog.details)
            .all()
        )
        blocked_reasons = [
            {"reason": reason, "count": count} for reason, count in blocked_rows
        ]

        return ComplianceSummary(
            program_id=program_id,
            total_actions=total,
            allowed_actions=allowed,
            blocked_actions=blocked,
            blocked_reasons=blocked_reasons,
        )

    def load_program_rules(
        self, program_id: str, db: Session
    ) -> list[ProgramRule]:
        """Загружает правила для указанной программы из БД.

        Обеспечивает изоляцию: возвращаются только правила выбранной программы.

        Args:
            program_id: идентификатор программы.
            db: сессия SQLAlchemy.

        Returns:
            Список Pydantic-моделей ProgramRule для данной программы.
        """
        rows = db.query(ProgramRuleDB).filter(
            ProgramRuleDB.program_id == program_id
        ).all()
        return [
            ProgramRule(
                id=row.id,
                description=row.description,
                is_allowed=row.is_allowed,
                category=row.category,
            )
            for row in rows
        ]

    def load_program_scope(
        self, program_id: str, db: Session
    ) -> list[Asset]:
        """Загружает активы (scope) для указанной программы из БД.

        Обеспечивает изоляцию: возвращаются только активы выбранной программы.

        Args:
            program_id: идентификатор программы.
            db: сессия SQLAlchemy.

        Returns:
            Список Pydantic-моделей Asset для данной программы.
        """
        rows = db.query(AssetDB).filter(
            AssetDB.program_id == program_id
        ).all()
        return [
            Asset(
                id=row.id,
                name=row.name,
                asset_type=AssetType(row.asset_type),
                target=row.target,
                in_scope=row.in_scope,
                notes=row.notes,
            )
            for row in rows
        ]

    @staticmethod
    def _extract_keywords(text: str) -> set[str]:
        """Извлекает ключевые слова из текста (lowercase, длина >= 3)."""
        return {
            word
            for word in text.lower().split()
            if len(word) >= 3
        }

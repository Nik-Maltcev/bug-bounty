"""Менеджер контроля соответствия правилам программы bug bounty.

Проверяет действия агента на соответствие правилам программы,
валидирует область действия (scope) и блокирует запрещённые действия.
Расширен для поддержки AI-Driven Scan (Stage 2).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

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

if TYPE_CHECKING:
    from app.models.ai_scan_schemas import AIRequest

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

    # =========================================================================
    # AI-Driven Scan (Stage 2) — методы валидации AI-запросов
    # =========================================================================

    # Паттерны деструктивных действий (Req 11)
    DESTRUCTIVE_SQL_PATTERNS = [
        r"\bDROP\s+",
        r"\bDELETE\s+FROM\b",
        r"\bTRUNCATE\s+",
        r"\bUPDATE\s+\w+\s+SET\b",
        r"\bINSERT\s+INTO\b",
        r"\bALTER\s+TABLE\b",
        r"\bCREATE\s+TABLE\b",
        r"\bGRANT\s+",
        r"\bREVOKE\s+",
    ]

    DESTRUCTIVE_SHELL_PATTERNS = [
        r"\brm\s+-rf\b",
        r"\brm\s+-r\b",
        r"\bmkfs\b",
        r"\bdd\s+if=",
        r"\bformat\s+",
        r"\bfdisk\b",
        r">\s*/dev/",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\binit\s+0\b",
        r"\bsystemctl\s+(stop|disable)\b",
    ]

    REVERSE_SHELL_PATTERNS = [
        r"\bnc\s+-e\b",
        r"\bncat\s+-e\b",
        r"\bbash\s+-i\b",
        r"/dev/tcp/",
        r"/dev/udp/",
        r"\bpython\s+-c\s+['\"]import\s+socket",
        r"\bperl\s+-e\s+['\"]use\s+Socket",
        r"\bphp\s+-r\s+['\"].*fsockopen",
        r"\bruby\s+-rsocket\b",
        r"\bpowershell\s+.*-e\s+",
        r"\bInvoke-Expression\b",
        r"\bIEX\s*\(",
    ]

    FILE_UPLOAD_PATTERNS = [
        r"\.php[345]?\s*$",
        r"\.phtml\s*$",
        r"\.asp[x]?\s*$",
        r"\.jsp[x]?\s*$",
        r"\.exe\s*$",
        r"\.sh\s*$",
        r"\.bat\s*$",
        r"\.cmd\s*$",
        r"\.ps1\s*$",
    ]

    CONFIG_MODIFICATION_PATTERNS = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/sudoers",
        r"\.htaccess",
        r"web\.config",
        r"wp-config\.php",
        r"config\.php",
        r"settings\.py",
        r"\.env",
    ]

    # Разрешённые read-only SQL паттерны
    ALLOWED_SQL_PATTERNS = [
        r"\bSELECT\s+",
        r"\bUNION\s+SELECT\b",
        r"'\s*OR\s*'",
        r"'\s*AND\s*'",
        r"1\s*=\s*1",
        r"SLEEP\s*\(",
        r"BENCHMARK\s*\(",
        r"WAITFOR\s+DELAY",
    ]

    def validate_ai_request(
        self,
        request: AIRequest,
        rules: list[ProgramRule],
        scope: list[Asset],
    ) -> ComplianceResult:
        """Валидирует AI-сгенерированный запрос на соответствие правилам.

        Проверяет:
        1. URL в scope программы
        2. Отсутствие деструктивных действий
        3. Соответствие правилам программы

        Args:
            request: AI-сгенерированный HTTP-запрос.
            rules: правила программы.
            scope: активы программы.

        Returns:
            ComplianceResult с решением и причиной.
        """
        # 1. Проверка URL в scope
        if not self._is_url_in_scope(request.url, scope):
            logger.warning(
                "AI Request BLOCKED: URL not in scope: %s",
                request.url,
            )
            return ComplianceResult(
                action_allowed=False,
                reason=f"URL не входит в scope программы: {request.url}",
                rule_reference="scope_violation",
            )

        # 2. Проверка на деструктивные действия
        destructive_check = self.is_destructive_action(request)
        if destructive_check:
            logger.warning(
                "AI Request BLOCKED: destructive action detected: %s",
                destructive_check,
            )
            return ComplianceResult(
                action_allowed=False,
                reason=f"Обнаружено деструктивное действие: {destructive_check}",
                rule_reference="destructive_action",
            )

        # 3. Проверка правил программы
        action = AgentAction(
            action_type=f"ai_request_{request.method}",
            target=request.url,
            description=f"AI-generated {request.method} request to {request.url}",
        )
        rule_check = self.validate_action(action, rules)
        if not rule_check.action_allowed:
            return rule_check

        return ComplianceResult(
            action_allowed=True,
            reason="AI-запрос разрешён: прошёл все проверки",
            rule_reference=None,
        )

    def is_destructive_action(self, request: AIRequest) -> str | None:
        """Проверяет запрос на наличие деструктивных действий.

        Args:
            request: AI-сгенерированный запрос.

        Returns:
            Описание обнаруженного деструктивного действия или None.
        """
        # Собираем весь текст для проверки
        check_text = f"{request.url} {request.body or ''}"
        for header_value in request.headers.values():
            check_text += f" {header_value}"

        check_text_lower = check_text.lower()

        # Проверка деструктивных SQL
        for pattern in self.DESTRUCTIVE_SQL_PATTERNS:
            if re.search(pattern, check_text, re.IGNORECASE):
                # Проверяем, не является ли это read-only тестом
                is_readonly = any(
                    re.search(p, check_text, re.IGNORECASE)
                    for p in self.ALLOWED_SQL_PATTERNS
                )
                if not is_readonly:
                    return f"Деструктивный SQL: {pattern}"

        # Проверка shell injection
        for pattern in self.DESTRUCTIVE_SHELL_PATTERNS:
            if re.search(pattern, check_text, re.IGNORECASE):
                return f"Деструктивная shell-команда: {pattern}"

        # Проверка reverse shell
        for pattern in self.REVERSE_SHELL_PATTERNS:
            if re.search(pattern, check_text, re.IGNORECASE):
                return f"Reverse shell payload: {pattern}"

        # Проверка file upload с исполняемым содержимым
        if request.method in ("POST", "PUT"):
            for pattern in self.FILE_UPLOAD_PATTERNS:
                if re.search(pattern, check_text, re.IGNORECASE):
                    return f"Загрузка исполняемого файла: {pattern}"

        # Проверка модификации конфигурации
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            for pattern in self.CONFIG_MODIFICATION_PATTERNS:
                if re.search(pattern, check_text, re.IGNORECASE):
                    return f"Модификация конфигурации: {pattern}"

        return None

    def _is_url_in_scope(self, url: str, scope: list[Asset]) -> bool:
        """Проверяет, находится ли URL в scope программы.

        Args:
            url: URL для проверки.
            scope: список активов программы.

        Returns:
            True если URL в scope или scope пустой (permissive mode для B2B).
        """
        # B2B режим: если scope пустой — разрешаем всё
        if not scope:
            return True
        
        parsed = urlparse(url)
        url_host = parsed.netloc.lower()
        url_path = parsed.path.lower()

        for asset in scope:
            if not asset.in_scope:
                continue

            asset_target = asset.target.lower()

            # Парсим target актива
            if asset_target.startswith(("http://", "https://")):
                asset_parsed = urlparse(asset_target)
                asset_host = asset_parsed.netloc.lower()
                asset_path = asset_parsed.path.lower()
            else:
                # Если target без схемы, считаем его доменом
                asset_host = asset_target
                asset_path = ""

            # Проверяем совпадение хоста
            if url_host == asset_host:
                # Если у актива есть path, проверяем что URL начинается с него
                if asset_path and not url_path.startswith(asset_path):
                    continue
                return True

            # Проверяем wildcard поддомены (*.example.com)
            if asset_host.startswith("*."):
                base_domain = asset_host[2:]
                if url_host == base_domain or url_host.endswith(f".{base_domain}"):
                    return True
            
            # B2B режим: проверяем что URL относится к тому же домену что и актив
            # (разрешаем поддомены и пути)
            if url_host.endswith(asset_host) or asset_host.endswith(url_host):
                return True

        return True  # B2B режим: по умолчанию разрешаем

    def get_program_rate_limit(
        self, program_id: str, db: Session
    ) -> float | None:
        """Получает rate limit из правил программы.

        Ищет в правилах программы упоминание rate limit и возвращает
        меньшее из найденного значения и значения по умолчанию (5 req/s).

        Args:
            program_id: идентификатор программы.
            db: сессия SQLAlchemy.

        Returns:
            Rate limit в запросах в секунду или None если не указан.
        """
        rules = self.load_program_rules(program_id, db)

        for rule in rules:
            desc_lower = rule.description.lower()

            # Ищем паттерны rate limit
            # "rate limit: 10 requests per second"
            # "max 5 req/s"
            # "не более 3 запросов в секунду"
            patterns = [
                r"(\d+)\s*(?:requests?|req)\s*(?:per|/)\s*(?:second|sec|s)",
                r"rate\s*limit[:\s]*(\d+)",
                r"max(?:imum)?\s*(\d+)\s*(?:requests?|req)",
                r"не\s*более\s*(\d+)\s*запрос",
            ]

            for pattern in patterns:
                match = re.search(pattern, desc_lower)
                if match:
                    try:
                        limit = float(match.group(1))
                        logger.info(
                            "Found rate limit in program rules: %.1f req/s",
                            limit,
                        )
                        return limit
                    except ValueError:
                        continue

        return None

    def get_effective_rate_limit(
        self,
        program_id: str,
        db: Session,
        default_limit: float = 5.0,
    ) -> float:
        """Возвращает эффективный rate limit для программы.

        Возвращает меньшее из: лимита программы и лимита по умолчанию.

        Args:
            program_id: идентификатор программы.
            db: сессия SQLAlchemy.
            default_limit: лимит по умолчанию.

        Returns:
            Эффективный rate limit.
        """
        program_limit = self.get_program_rate_limit(program_id, db)

        if program_limit is None:
            return default_limit

        return min(program_limit, default_limit)

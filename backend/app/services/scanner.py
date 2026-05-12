"""Сканер уязвимостей веб-сайтов с модульной системой проверок.

Содержит:
- Scanner — основной класс сканирования с поддержкой веб-плагинов
- classify_severity — классификация находок по уровню серьёзности
- Сохранение находок в БД
"""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.schemas import (
    ActionResult,
    Asset,
    AssetType,
    AuditEntry,
    RawFinding,
    ScanConfig,
    ScanProgress,
    ScanStatus,
    SeverityLevel,
)
from app.models.database import Scan, VulnerabilityRecord
from app.services.compliance_manager import AgentAction, ComplianceManager
from app.services.scan_plugins.base import ScanPlugin
from app.services.scan_plugins.real_web_plugin import RealWebPlugin
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.audit_logger import AuditLogger
from app.services.vulnerability_knowledge import enrich_vulnerability
from app.core.exceptions import ScanError

logger = logging.getLogger(__name__)

# Ключевые слова для классификации серьёзности
_CRITICAL_KEYWORDS = {
    "rce", "remote code execution", "injection",
    "sql_injection", "command_injection", "deserialization",
    "lfi", "local file inclusion", "rfi", "remote file inclusion",
    "ssrf", "server-side request forgery",
}
_HIGH_KEYWORDS = {
    "xss", "cross-site scripting", "broken_authentication",
    "authentication", "access_control", "privilege_escalation",
    "idor", "insecure direct object reference",
    "path_traversal", "directory_traversal",
    "xml_external_entity", "xxe",
}
_MEDIUM_KEYWORDS = {
    "csrf", "cross-site request forgery", "data_exposure",
    "excessive_data_exposure", "information_disclosure",
    "missing_security_headers", "cors_misconfiguration",
    "clickjacking", "missing_rate_limiting",
}
_LOW_KEYWORDS = {
    "open_redirect", "redirect", "rate_limiting",
    "informational", "waf_detected", "technology_fingerprint",
    "subdomain", "directory_listing",
}


class Scanner:
    """Сканер уязвимостей с модульной системой проверок."""

    def __init__(self) -> None:
        self._sessions: dict[str, ScanProgress] = {}
        self._plugins: dict[AssetType, ScanPlugin] = {
            AssetType.WEB_APPLICATION: RealWebPlugin(),
        }
        self._audit_logger = AuditLogger()
        self._orchestrator = ScanOrchestrator()

    def get_plugin_for_asset(self, asset_type: AssetType) -> ScanPlugin | None:
        """Возвращает плагин для указанного типа актива."""
        return self._plugins.get(asset_type)

    def get_checks_for_asset_type(self, asset_type: AssetType) -> list[str]:
        """Возвращает список проверок для типа актива."""
        plugin = self._plugins.get(asset_type)
        if plugin is None:
            return []
        return plugin.get_check_names()

    def start_scan(
        self,
        asset: Asset,
        scan_config: ScanConfig,
        compliance_manager: ComplianceManager,
        rules: list,
        db: Session,
    ) -> ScanProgress:
        """Запускает сканирование актива.

        Каждое действие сканера проходит через ComplianceManager.validate_action.
        Находки классифицируются и сохраняются в БД.

        Args:
            asset: актив для сканирования.
            scan_config: конфигурация сканирования.
            compliance_manager: менеджер соответствия для валидации действий.
            rules: правила программы для валидации.
            db: сессия SQLAlchemy.

        Returns:
            ScanProgress с результатами сканирования.

        Raises:
            ScanError: если плагин для типа актива не найден.
        """
        scan_id = str(uuid.uuid4())

        # Создаём запись сканирования в БД
        scan_record = Scan(
            id=scan_id,
            program_id=scan_config.program_id,
            asset_id=asset.id,
            status=ScanStatus.RUNNING.value,
            current_stage="initializing",
            percent_complete=0,
            started_at=datetime.now(UTC),
        )
        db.add(scan_record)
        db.commit()

        # Инициализируем прогресс
        progress = ScanProgress(
            scan_id=scan_id,
            status=ScanStatus.RUNNING,
            current_stage="initializing",
            percent_complete=0,
            findings_count=0,
        )
        self._sessions[scan_id] = progress

        # Валидация действия через ComplianceManager
        action = AgentAction(
            action_type="scan",
            target=asset.target,
            description=f"Security scan of {asset.asset_type.value} asset {asset.target}",
        )
        compliance_result = compliance_manager.validate_action(action, rules)

        if not compliance_result.action_allowed:
            # Log blocked action to audit
            self._log_action(
                action=action,
                result=ActionResult.BLOCKED,
                program_id=scan_config.program_id,
                rule_reference=compliance_result.rule_reference or "",
                details=compliance_result.reason,
                db=db,
            )
            progress.status = ScanStatus.FAILED
            progress.current_stage = "blocked_by_compliance"
            scan_record.status = ScanStatus.FAILED.value
            scan_record.current_stage = "blocked_by_compliance"
            db.commit()
            self._sessions[scan_id] = progress
            return progress

        # Log allowed scan action to audit
        self._log_action(
            action=action,
            result=ActionResult.ALLOWED,
            program_id=scan_config.program_id,
            rule_reference=compliance_result.rule_reference or "",
            details=compliance_result.reason,
            db=db,
        )

        # Выбираем плагин по типу актива
        plugin = self._plugins.get(asset.asset_type)
        if plugin is None:
            progress.status = ScanStatus.FAILED
            progress.current_stage = "no_plugin"
            scan_record.status = ScanStatus.FAILED.value
            scan_record.current_stage = "no_plugin"
            db.commit()
            self._sessions[scan_id] = progress
            raise ScanError(scan_id, "plugin_selection", f"No plugin for asset type: {asset.asset_type.value}")

        # Обновляем прогресс: сканирование
        progress.current_stage = "scanning"
        progress.percent_complete = 10
        self._sessions[scan_id] = progress
        scan_record.current_stage = "scanning"
        scan_record.percent_complete = 10
        db.commit()

        try:
            raw_findings = plugin.scan(asset, scan_config)
        except Exception as e:
            progress.status = ScanStatus.FAILED
            progress.current_stage = "scan_error"
            scan_record.status = ScanStatus.FAILED.value
            scan_record.current_stage = "scan_error"
            db.commit()
            self._sessions[scan_id] = progress
            raise ScanError(scan_id, "scanning", str(e))

        # Классификация и сохранение находок
        progress.current_stage = "classifying"
        progress.percent_complete = 70
        self._sessions[scan_id] = progress
        scan_record.current_stage = "classifying"
        scan_record.percent_complete = 70
        db.commit()

        for finding in raw_findings:
            severity = self.classify_severity(finding)
            self._save_finding(finding, severity, scan_id, scan_config.program_id, db)

        # Завершение
        progress.status = ScanStatus.COMPLETED
        progress.current_stage = "completed"
        progress.percent_complete = 100
        progress.findings_count = len(raw_findings)
        self._sessions[scan_id] = progress

        scan_record.status = ScanStatus.COMPLETED.value
        scan_record.current_stage = "completed"
        scan_record.percent_complete = 100
        scan_record.completed_at = datetime.now(UTC)
        db.commit()

        return progress

    def get_scan_progress(self, scan_id: str) -> ScanProgress | None:
        """Возвращает прогресс текущего сканирования.

        Args:
            scan_id: идентификатор сканирования.

        Returns:
            ScanProgress или None, если сканирование не найдено.
        """
        return self._sessions.get(scan_id)

    @staticmethod
    def classify_severity(finding: RawFinding) -> SeverityLevel:
        """Классифицирует уязвимость по уровню серьёзности.

        Использует keyword-based эвристику на основе типа уязвимости
        и описания находки.

        Args:
            finding: сырая находка сканера.

        Returns:
            SeverityLevel: Critical, High, Medium, Low, Informational.
        """
        text = f"{finding.vulnerability_type} {finding.description}".lower()

        for keyword in _CRITICAL_KEYWORDS:
            if keyword in text:
                return SeverityLevel.CRITICAL

        for keyword in _HIGH_KEYWORDS:
            if keyword in text:
                return SeverityLevel.HIGH

        for keyword in _MEDIUM_KEYWORDS:
            if keyword in text:
                return SeverityLevel.MEDIUM

        for keyword in _LOW_KEYWORDS:
            if keyword in text:
                return SeverityLevel.LOW

        return SeverityLevel.INFORMATIONAL

    @staticmethod
    def _save_finding(
        finding: RawFinding,
        severity: SeverityLevel,
        scan_id: str,
        program_id: str,
        db: Session,
    ) -> VulnerabilityRecord:
        """Сохраняет классифицированную находку в БД.

        Обогащает данные информацией из базы знаний по уязвимостям.

        Args:
            finding: сырая находка.
            severity: уровень серьёзности.
            scan_id: идентификатор сканирования.
            program_id: идентификатор программы.
            db: сессия SQLAlchemy.

        Returns:
            Созданная запись VulnerabilityRecord.
        """
        # Обогащаем данные из базы знаний
        enriched = enrich_vulnerability(
            vuln_type=finding.vulnerability_type,
            description=finding.description,
            evidence=finding.evidence,
        )
        
        # Переопределяем серьёзность если указано в базе знаний
        final_severity = severity
        if enriched.get("severity_override"):
            try:
                final_severity = SeverityLevel(enriched["severity_override"])
            except ValueError:
                pass
        
        record = VulnerabilityRecord(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            program_id=program_id,
            vulnerability_type=finding.vulnerability_type,
            severity=final_severity.value,
            description=enriched["description"],
            steps_to_reproduce=enriched["steps_to_reproduce"],
            evidence=finding.evidence,
            impact_assessment=enriched["impact_assessment"],
            remediation=enriched["remediation"],
            status="new",
        )
        db.add(record)
        db.commit()
        return record

    def _log_action(
        self,
        action: AgentAction,
        result: ActionResult,
        program_id: str,
        rule_reference: str,
        details: str,
        db: Session,
    ) -> None:
        """Записывает действие сканера в журнал аудита."""
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            action_type=action.action_type,
            target_asset=action.target,
            result=result,
            program_id=program_id,
            rule_reference=rule_reference,
            details=details,
        )
        self._audit_logger.log(entry, db)

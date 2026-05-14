"""AIScanner — главный класс AI-Driven Scan (Stage 2).

Координирует все компоненты второго этапа сканирования:
извлечение технологий, генерацию гипотез, выполнение запросов,
анализ ответов и формирование отчёта.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from app.models.ai_scan_schemas import (
    AIAuditType,
    AIFinding,
    AIRequest,
    AIRequestStatus,
    AIScanResult,
    HypothesisStatus,
    Stage2Status,
    TechnologyFingerprint,
)
from app.models.database import (
    AIFindingRecord,
    AIRequestRecord,
    AIScanState,
    AITestHypothesis,
    AITechnologyFingerprint,
    VulnerabilityRecord,
)
from app.models.schemas import RawFinding
from app.services.ai.hypothesis_engine import HypothesisEngine
from app.services.ai.iteration_manager import IterationManager
from app.services.ai.llm_provider_manager import LLMProviderManager
from app.services.ai.rate_limiter import RateLimiter
from app.services.ai.request_executor import RequestExecutor
from app.services.ai.response_analyzer import ResponseAnalyzer
from app.services.ai.supervised_handler import SyncSupervisedHandler
from app.services.ai.tech_extractor import TechExtractor
from app.services.audit_logger import AuditLogger
from app.services.compliance_manager import ComplianceManager
from app.services.process_manager import ProcessManager

if TYPE_CHECKING:
    from app.models.schemas import Asset, ProgramRule

logger = logging.getLogger(__name__)


class AIScanner:
    """AI-управляемый сканер второго этапа."""

    DEFAULT_MAX_ITERATIONS = 7
    DEFAULT_MAX_REQUESTS = 100
    DEFAULT_RATE_LIMIT = 5.0

    def __init__(
        self,
        llm_manager: LLMProviderManager,
        process_manager: ProcessManager | None = None,
        compliance_manager: ComplianceManager | None = None,
        audit_logger: AuditLogger | None = None,
        db: Session | None = None,
    ) -> None:
        """Инициализация AI Scanner.

        Args:
            llm_manager: менеджер LLM.
            process_manager: менеджер процессов.
            compliance_manager: менеджер compliance.
            audit_logger: логгер аудита.
            db: сессия SQLAlchemy.
        """
        self._llm = llm_manager
        self._process_manager = process_manager or ProcessManager()
        self._compliance = compliance_manager or ComplianceManager()
        self._audit = audit_logger or AuditLogger()
        self._db = db

        # Компоненты Stage 2
        self._tech_extractor = TechExtractor(llm_manager)
        self._hypothesis_engine = HypothesisEngine(llm_manager)
        self._response_analyzer = ResponseAnalyzer(llm_manager)

        # Состояние
        self._stopped = False
        self._current_scan_id: str | None = None

    def run_stage2(
        self,
        scan_id: str,
        stage1_results: list[RawFinding],
        target_url: str,
        program_id: str,
        rules: list[ProgramRule] | None = None,
        scope: list[Asset] | None = None,
        supervised_mode: bool = False,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        rate_limit: float = DEFAULT_RATE_LIMIT,
    ) -> AIScanResult:
        """Выполняет второй этап сканирования.

        Args:
            scan_id: ID сканирования.
            stage1_results: результаты Stage 1.
            target_url: базовый URL цели.
            program_id: ID программы.
            rules: правила программы.
            scope: активы программы.
            supervised_mode: режим с одобрением.
            max_iterations: максимум итераций.
            max_requests: максимум запросов.
            rate_limit: лимит запросов в секунду.

        Returns:
            Результат AI-сканирования.
        """
        self._stopped = False
        self._current_scan_id = scan_id
        started_at = datetime.now(UTC)

        rules = rules or []
        scope = scope or []

        # Инициализируем компоненты для этого сканирования
        iteration_manager = IterationManager(max_iterations, max_requests)
        rate_limiter = RateLimiter(rate_limit)
        request_executor = RequestExecutor(self._process_manager, rate_limiter, rate_limit)
        supervised_handler = SyncSupervisedHandler(auto_approve=not supervised_mode)

        # Сохраняем состояние в БД
        self._init_scan_state(scan_id, supervised_mode, max_iterations, max_requests, rate_limit)

        # Результаты
        technologies: list[TechnologyFingerprint] = []
        findings: list[AIFinding] = []
        all_results = []

        try:
            # === Фаза 1: Извлечение технологий ===
            self._update_phase(scan_id, "tech_extraction")
            logger.info("Stage 2 [%s]: Starting technology extraction", scan_id)

            technologies = self._tech_extractor.extract(stage1_results)

            for tech in technologies:
                self._save_technology(scan_id, tech)
                self._log_ai_decision(
                    scan_id, AIAuditType.TECH_EXTRACTED, "extracted",
                    reasoning=f"Extracted {tech.name} v{tech.version} from {tech.source}",
                    details={"technology": tech.name, "version": tech.version, "category": tech.category.value},
                )

            self._update_stats(scan_id, technologies_found=len(technologies))

            if self._stopped:
                return self._build_cancelled_result(scan_id, technologies, findings, started_at)

            # === Фаза 2: Итеративное тестирование ===
            self._update_phase(scan_id, "hypothesis_testing")

            for iteration in range(max_iterations):
                if self._stopped or not iteration_manager.can_continue():
                    break

                iteration_manager.start_iteration(iteration)
                self._log_ai_decision(
                    scan_id, AIAuditType.ITERATION_STARTED, "started",
                    iteration=iteration,
                    reasoning=f"Starting iteration {iteration}",
                )

                # Генерируем гипотезы
                hypotheses = self._hypothesis_engine.generate(
                    scan_id=scan_id,
                    fingerprints=technologies,
                    findings=stage1_results,
                    target_url=target_url,
                    iteration=iteration,
                    previous_results=all_results[-10:] if all_results else None,
                )

                if not hypotheses:
                    logger.info("Stage 2 [%s]: No hypotheses generated for iteration %d", scan_id, iteration)
                    break

                self._update_stats(scan_id, hypotheses_generated=len(hypotheses))

                # Тестируем каждую гипотезу
                for hypothesis in hypotheses:
                    if self._stopped or not iteration_manager.can_add_request():
                        break

                    # Записываем гипотезу
                    iteration_manager.record_hypothesis(
                        hypothesis.id,
                        hypothesis.parent_hypothesis_id,
                        hypothesis.vulnerability_type,
                        hypothesis.description,
                    )
                    self._save_hypothesis(scan_id, hypothesis)
                    self._log_ai_decision(
                        scan_id, AIAuditType.HYPOTHESIS_GENERATED, "generated",
                        hypothesis_id=hypothesis.id,
                        iteration=iteration,
                        parent_test_id=hypothesis.parent_hypothesis_id,
                        reasoning=hypothesis.rationale,
                        details={"type": hypothesis.vulnerability_type, "target": hypothesis.target_url},
                    )

                    # Создаём запрос
                    ai_request = self._hypothesis_engine.create_request(hypothesis)
                    self._save_request(hypothesis.id, ai_request)
                    self._log_ai_decision(
                        scan_id, AIAuditType.REQUEST_CREATED, "created",
                        hypothesis_id=hypothesis.id,
                        request_id=ai_request.id,
                        iteration=iteration,
                        details={"method": ai_request.method, "url": ai_request.url},
                    )

                    # Проверка compliance
                    compliance_result = self._compliance.validate_ai_request(ai_request, rules, scope)
                    self._log_ai_decision(
                        scan_id, AIAuditType.COMPLIANCE_CHECK,
                        "allowed" if compliance_result.action_allowed else "blocked",
                        hypothesis_id=hypothesis.id,
                        request_id=ai_request.id,
                        iteration=iteration,
                        reasoning=compliance_result.reason,
                    )

                    if not compliance_result.action_allowed:
                        self._update_request_status(ai_request.id, AIRequestStatus.COMPLIANCE_BLOCKED, compliance_result.reason)
                        self._update_hypothesis_status(hypothesis.id, HypothesisStatus.BLOCKED)
                        iteration_manager.record_result(hypothesis.id, confirmed=False, blocked=True)
                        self._update_stats(scan_id, requests_blocked=1)
                        continue

                    # Supervised mode
                    if supervised_mode:
                        approved = supervised_handler.request_approval(
                            scan_id, hypothesis, ai_request
                        )
                        decision = "approved" if approved else "rejected"
                        self._log_ai_decision(
                            scan_id,
                            AIAuditType.USER_APPROVED if approved else AIAuditType.USER_REJECTED,
                            decision,
                            hypothesis_id=hypothesis.id,
                            request_id=ai_request.id,
                            iteration=iteration,
                        )

                        if not approved:
                            self._update_request_status(ai_request.id, AIRequestStatus.USER_REJECTED)
                            self._update_hypothesis_status(hypothesis.id, HypothesisStatus.REJECTED)
                            iteration_manager.record_result(hypothesis.id, confirmed=False)
                            continue

                    # Выполняем запрос
                    self._update_request_status(ai_request.id, AIRequestStatus.EXECUTING)
                    result = request_executor.execute(ai_request)
                    iteration_manager.record_request(hypothesis.id)
                    all_results.append(result)

                    self._save_request_result(ai_request.id, result)
                    self._log_ai_decision(
                        scan_id, AIAuditType.REQUEST_EXECUTED, "executed",
                        hypothesis_id=hypothesis.id,
                        request_id=ai_request.id,
                        iteration=iteration,
                        details={"status_code": result.status_code, "duration_ms": result.duration_ms},
                    )
                    self._update_stats(scan_id, requests_executed=1)

                    # Анализируем ответ
                    self._update_phase(scan_id, "analysis")
                    analysis = self._response_analyzer.analyze(hypothesis, ai_request, result)

                    self._save_analysis(ai_request.id, analysis)
                    self._log_ai_decision(
                        scan_id, AIAuditType.RESPONSE_ANALYZED, "analyzed",
                        hypothesis_id=hypothesis.id,
                        request_id=ai_request.id,
                        iteration=iteration,
                        reasoning=analysis.reasoning,
                        details={"confirmed": analysis.is_confirmed, "confidence": analysis.confidence},
                    )

                    # Обрабатываем результат
                    if analysis.is_confirmed:
                        self._update_hypothesis_status(hypothesis.id, HypothesisStatus.CONFIRMED)
                        iteration_manager.record_result(hypothesis.id, confirmed=True)

                        # Создаём finding
                        finding = self._create_finding(scan_id, hypothesis, ai_request, result, analysis)
                        findings.append(finding)
                        self._save_finding(finding, program_id)

                        self._log_ai_decision(
                            scan_id, AIAuditType.FINDING_CONFIRMED, "confirmed",
                            hypothesis_id=hypothesis.id,
                            request_id=ai_request.id,
                            iteration=iteration,
                            reasoning=analysis.reasoning,
                            details={"severity": analysis.severity, "confidence": analysis.confidence},
                        )
                        self._update_stats(scan_id, findings_confirmed=1)
                    else:
                        self._update_hypothesis_status(hypothesis.id, HypothesisStatus.REFUTED)
                        iteration_manager.record_result(hypothesis.id, confirmed=False)

                    self._update_stats(scan_id, hypotheses_tested=1)

            # === Завершение ===
            self._update_phase(scan_id, "completed")
            self._log_ai_decision(
                scan_id, AIAuditType.SCAN_COMPLETED, "completed",
                reasoning=f"Stage 2 completed: {len(findings)} findings confirmed",
                details=iteration_manager.get_stats(),
            )

            return self._build_result(
                scan_id, "completed", technologies, findings,
                iteration_manager, started_at
            )

        except Exception as e:
            logger.exception("Stage 2 [%s] failed: %s", scan_id, e)
            self._update_phase(scan_id, "failed")
            return self._build_result(
                scan_id, "failed", technologies, findings,
                iteration_manager, started_at
            )

    def stop(self) -> None:
        """Kill Switch — немедленная остановка сканирования."""
        self._stopped = True
        if self._current_scan_id and self._db:
            self._update_phase(self._current_scan_id, "cancelled")
            self._log_ai_decision(
                self._current_scan_id, AIAuditType.SCAN_CANCELLED, "cancelled",
                reasoning="Kill switch activated",
            )
        logger.warning("AI Scanner stop requested")

    def is_stopped(self) -> bool:
        """Проверяет, остановлено ли сканирование."""
        return self._stopped

    def get_status(self, scan_id: str) -> Stage2Status | None:
        """Возвращает статус Stage 2 сканирования."""
        if not self._db:
            return None

        state = self._db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
        if not state:
            return None

        total_hypotheses = state.hypotheses_generated or 0
        tested = state.hypotheses_tested or 0
        percent = int((tested / total_hypotheses * 100) if total_hypotheses > 0 else 0)

        return Stage2Status(
            scan_id=scan_id,
            status=state.status,
            current_phase=state.current_phase,
            technologies_found=state.technologies_found,
            hypotheses_generated=state.hypotheses_generated,
            hypotheses_tested=state.hypotheses_tested,
            requests_executed=state.requests_executed,
            requests_blocked=state.requests_blocked,
            findings_confirmed=state.findings_confirmed,
            current_iteration=state.current_iteration,
            max_iterations=state.max_iterations,
            percent_complete=min(percent, 100),
            started_at=state.started_at,
            updated_at=state.updated_at,
        )

    # =========================================================================
    # Private methods
    # =========================================================================

    def _init_scan_state(
        self, scan_id: str, supervised_mode: bool,
        max_iterations: int, max_requests: int, rate_limit: float
    ) -> None:
        """Инициализирует состояние сканирования в БД."""
        if not self._db:
            return

        state = AIScanState(
            scan_id=scan_id,
            status="running",
            current_phase="initializing",
            supervised_mode=supervised_mode,
            max_iterations=max_iterations,
            max_requests=max_requests,
            rate_limit=rate_limit,
            started_at=datetime.now(UTC),
        )
        self._db.merge(state)
        self._db.commit()

    def _update_phase(self, scan_id: str, phase: str) -> None:
        """Обновляет текущую фазу сканирования."""
        if not self._db:
            return

        state = self._db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
        if state:
            state.current_phase = phase
            if phase in ("completed", "failed", "cancelled"):
                state.status = phase
                state.completed_at = datetime.now(UTC)
            self._db.commit()

    def _update_stats(self, scan_id: str, **kwargs) -> None:
        """Обновляет статистику сканирования."""
        if not self._db:
            return

        state = self._db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
        if state:
            for key, value in kwargs.items():
                if hasattr(state, key):
                    current = getattr(state, key) or 0
                    setattr(state, key, current + value)
            self._db.commit()

    def _save_technology(self, scan_id: str, tech: TechnologyFingerprint) -> None:
        """Сохраняет технологию в БД."""
        if not self._db:
            return

        import json
        record = AITechnologyFingerprint(
            id=tech.id,
            scan_id=scan_id,
            name=tech.name,
            version=tech.version,
            category=tech.category.value,
            source=tech.source,
            confidence=tech.confidence,
            raw_evidence=tech.raw_evidence,
            known_cves_json=json.dumps([c.model_dump() for c in tech.known_cves], ensure_ascii=False),
        )
        self._db.add(record)
        self._db.commit()

    def _save_hypothesis(self, scan_id: str, hypothesis) -> None:
        """Сохраняет гипотезу в БД."""
        if not self._db:
            return

        record = AITestHypothesis(
            id=hypothesis.id,
            scan_id=scan_id,
            description=hypothesis.description,
            rationale=hypothesis.rationale,
            target_url=hypothesis.target_url,
            vulnerability_type=hypothesis.vulnerability_type,
            severity_estimate=hypothesis.severity_estimate,
            source_fingerprint_id=hypothesis.source_fingerprint_id,
            source_finding_id=hypothesis.source_finding_id,
            parent_hypothesis_id=hypothesis.parent_hypothesis_id,
            iteration=hypothesis.iteration,
            status=hypothesis.status.value,
        )
        self._db.add(record)
        self._db.commit()

    def _save_request(self, hypothesis_id: str, request: AIRequest) -> None:
        """Сохраняет запрос в БД."""
        if not self._db:
            return

        import json
        record = AIRequestRecord(
            id=request.id,
            hypothesis_id=hypothesis_id,
            method=request.method,
            url=request.url,
            headers_json=json.dumps(request.headers, ensure_ascii=False),
            body=request.body,
            expected_indicators_json=json.dumps(request.expected_indicators, ensure_ascii=False),
            timeout_seconds=request.timeout_seconds,
            status=request.status.value,
        )
        self._db.add(record)
        self._db.commit()

    def _save_request_result(self, request_id: str, result) -> None:
        """Сохраняет результат запроса в БД."""
        if not self._db:
            return

        import json
        record = self._db.query(AIRequestRecord).filter(AIRequestRecord.id == request_id).first()
        if record:
            record.status = AIRequestStatus.COMPLETED.value if not result.error else AIRequestStatus.FAILED.value
            record.response_status_code = result.status_code
            record.response_headers_json = json.dumps(result.response_headers, ensure_ascii=False)
            record.response_body = result.response_body[:100000] if result.response_body else None
            record.duration_ms = result.duration_ms
            record.error = result.error
            record.executed_at = result.executed_at
            self._db.commit()

    def _save_analysis(self, request_id: str, analysis) -> None:
        """Сохраняет анализ в БД."""
        if not self._db:
            return

        from app.models.database import AIResponseAnalysis
        import json

        record = AIResponseAnalysis(
            id=uuid.uuid4().hex[:12],
            request_id=request_id,
            is_confirmed=analysis.is_confirmed,
            confidence=analysis.confidence,
            reasoning=analysis.reasoning,
            severity=analysis.severity,
            requires_manual_review=analysis.requires_manual_review,
            follow_up_hints_json=json.dumps(analysis.follow_up_hints, ensure_ascii=False),
        )
        self._db.add(record)
        self._db.commit()

    def _update_request_status(self, request_id: str, status: AIRequestStatus, reason: str | None = None) -> None:
        """Обновляет статус запроса."""
        if not self._db:
            return

        record = self._db.query(AIRequestRecord).filter(AIRequestRecord.id == request_id).first()
        if record:
            record.status = status.value
            if status == AIRequestStatus.COMPLIANCE_BLOCKED:
                record.compliance_status = "blocked"
                record.compliance_reason = reason
            self._db.commit()

    def _update_hypothesis_status(self, hypothesis_id: str, status: HypothesisStatus) -> None:
        """Обновляет статус гипотезы."""
        if not self._db:
            return

        record = self._db.query(AITestHypothesis).filter(AITestHypothesis.id == hypothesis_id).first()
        if record:
            record.status = status.value
            self._db.commit()

    def _create_finding(self, scan_id: str, hypothesis, request, result, analysis) -> AIFinding:
        """Создаёт AIFinding из подтверждённой гипотезы."""
        # Формируем PoC request
        poc_request = f"{request.method} {request.url}\n"
        for k, v in request.headers.items():
            poc_request += f"{k}: {v}\n"
        if request.body:
            poc_request += f"\n{request.body}"

        # Формируем PoC response (релевантная часть)
        poc_response = f"HTTP {result.status_code}\n"
        for k, v in result.response_headers.items():
            poc_response += f"{k}: {v}\n"
        poc_response += f"\n{result.response_body[:2000] if result.response_body else ''}"

        return AIFinding(
            id=uuid.uuid4().hex[:12],
            scan_id=scan_id,
            hypothesis_id=hypothesis.id,
            vulnerability_type=hypothesis.vulnerability_type,
            severity=analysis.severity,
            confidence=analysis.confidence,
            description=hypothesis.description,
            poc_request=poc_request,
            poc_response=poc_response,
            reasoning=analysis.reasoning,
            remediation="",  # TODO: генерировать через LLM
            requires_manual_review=analysis.requires_manual_review,
            source_technology=None,
            created_at=datetime.now(UTC),
        )

    def _save_finding(self, finding: AIFinding, program_id: str) -> None:
        """Сохраняет finding в БД."""
        if not self._db:
            return

        # Сохраняем в ai_findings
        record = AIFindingRecord(
            id=finding.id,
            scan_id=finding.scan_id,
            hypothesis_id=finding.hypothesis_id,
            vulnerability_type=finding.vulnerability_type,
            severity=finding.severity,
            confidence=finding.confidence,
            description=finding.description,
            poc_request=finding.poc_request,
            poc_response=finding.poc_response,
            reasoning=finding.reasoning,
            remediation=finding.remediation,
            requires_manual_review=finding.requires_manual_review,
            source_technology=finding.source_technology,
        )
        self._db.add(record)

        # Также сохраняем в vulnerabilities с source="ai_driven_scan"
        vuln_record = VulnerabilityRecord(
            id=f"ai_{finding.id}",
            scan_id=finding.scan_id,
            program_id=program_id,
            vulnerability_type=finding.vulnerability_type,
            severity=finding.severity,
            description=finding.description,
            steps_to_reproduce=finding.poc_request,
            evidence=finding.poc_response,
            impact_assessment=finding.reasoning,
            remediation=finding.remediation,
            status="new",
        )
        self._db.add(vuln_record)
        self._db.commit()

    def _log_ai_decision(
        self, scan_id: str, entry_type: AIAuditType, decision: str, **kwargs
    ) -> None:
        """Логирует решение AI."""
        if not self._db or not self._audit:
            return

        self._audit.log_ai_decision(
            scan_id=scan_id,
            entry_type=entry_type.value,
            decision=decision,
            db=self._db,
            **kwargs,
        )

    def _build_result(
        self, scan_id: str, status: str,
        technologies: list[TechnologyFingerprint],
        findings: list[AIFinding],
        iteration_manager: IterationManager,
        started_at: datetime,
    ) -> AIScanResult:
        """Строит результат сканирования."""
        return AIScanResult(
            scan_id=scan_id,
            status=status,
            technologies=technologies,
            hypotheses_tested=iteration_manager.total_hypotheses,
            hypotheses_confirmed=iteration_manager.confirmed_count,
            requests_executed=iteration_manager.total_requests,
            requests_blocked=iteration_manager.get_state().blocked_count,
            findings=findings,
            investigation_tree=iteration_manager.get_tree(),
            audit_trail_id=scan_id,
            duration_seconds=(datetime.now(UTC) - started_at).total_seconds(),
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    def _build_cancelled_result(
        self, scan_id: str,
        technologies: list[TechnologyFingerprint],
        findings: list[AIFinding],
        started_at: datetime,
    ) -> AIScanResult:
        """Строит результат для отменённого сканирования."""
        return AIScanResult(
            scan_id=scan_id,
            status="cancelled",
            technologies=technologies,
            hypotheses_tested=0,
            hypotheses_confirmed=0,
            requests_executed=0,
            requests_blocked=0,
            findings=findings,
            investigation_tree={},
            audit_trail_id=scan_id,
            duration_seconds=(datetime.now(UTC) - started_at).total_seconds(),
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

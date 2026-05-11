"""AI API-эндпоинты: чат, настройки LLM, анализ, отчёты, рекомендации."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.ai_schemas import (
    ChatMessageResponse,
    ChatRequest,
    ChatResponse,
    FindingAnalysis,
    FindingAnalysisResponse,
    LLMConfig,
    LLMSettingsRequest,
    LLMSettingsResponse,
    ReportImproveRequest,
    RuleAnalysisResult,
    SessionContext,
)
from app.models.database import FindingAnalysisRecord, VulnerabilityRecord
from app.models.database import Report as ReportDB
from app.models.schemas import (
    ParsedProgram,
    RawFinding,
    Report,
    SeverityLevel,
    Vulnerability,
)
from app.services.ai.ai_controller import AIController
from app.services.ai.ai_report_generator import AIReportGenerator
from app.services.ai.finding_analyzer import FindingAnalyzer
from app.services.ai.llm_provider_manager import LLMProviderManager
from app.services.ai.rule_analyzer import RuleAnalyzer
from app.services.compliance_manager import ComplianceManager
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/api/ai", tags=["ai"])


def _get_llm_manager(db: Session) -> LLMProviderManager:
    return LLMProviderManager(db_session=db)


def _get_controller(db: Session) -> AIController:
    llm = _get_llm_manager(db)
    return AIController(llm_manager=llm, db=db)


# --- Chat endpoints ---


@router.post("/chat", response_model=ChatResponse)
def send_chat_message(
    request: ChatRequest,
    db: Session = Depends(get_db),
):
    """Отправка сообщения в чат."""
    controller = _get_controller(db)
    return controller.handle_message(request.program_id, request.message)


@router.get("/chat/{program_id}/history", response_model=list[ChatMessageResponse])
def get_chat_history(
    program_id: str,
    db: Session = Depends(get_db),
):
    """История диалога для программы."""
    controller = _get_controller(db)
    messages = controller.get_conversation_history(program_id)
    return [
        ChatMessageResponse(
            id=m.id,
            role=m.role,
            content=m.content,
            intent=m.intent,
            metadata=m.metadata,
            created_at=m.created_at,
        )
        for m in messages
    ]


@router.delete("/chat/{program_id}/history")
def clear_chat_history(
    program_id: str,
    db: Session = Depends(get_db),
):
    """Очистка истории диалога."""
    controller = _get_controller(db)
    controller.clear_conversation_history(program_id)
    return {"status": "ok", "message": "История чата очищена"}


# --- LLM Settings endpoints ---


@router.get("/settings", response_model=LLMSettingsResponse)
def get_llm_settings(db: Session = Depends(get_db)):
    """Текущие настройки LLM-провайдера."""
    mgr = _get_llm_manager(db)
    config = mgr.load_provider_config()
    if config is None:
        return LLMSettingsResponse(
            provider="deepseek",
            base_url="https://api.deepseek.com",
            model="deepseek-v4-flash",
            max_tokens=4096,
            temperature=0.3,
            is_connected=False,
        )
    connected = False
    try:
        connected = mgr.test_connection(config)
    except Exception:
        pass
    return LLMSettingsResponse(
        provider=config.provider,
        base_url=config.base_url,
        model=config.model,
        max_tokens=config.max_tokens,
        temperature=config.temperature,
        is_connected=connected,
    )


@router.put("/settings")
def update_llm_settings(
    request: LLMSettingsRequest,
    db: Session = Depends(get_db),
):
    """Обновление настроек LLM-провайдера."""
    mgr = _get_llm_manager(db)
    config = LLMConfig(
        provider=request.provider,
        api_key=request.api_key,
        base_url=request.base_url,
        model=request.model,
        max_tokens=request.max_tokens,
        temperature=request.temperature,
    )
    mgr.save_provider_config(config)
    return {"status": "ok", "message": "Настройки обновлены"}


@router.post("/settings/test")
def test_llm_connection(db: Session = Depends(get_db)):
    """Тест подключения к провайдеру."""
    mgr = _get_llm_manager(db)
    config = mgr.load_provider_config()
    if config is None:
        return {"connected": False, "error": "Провайдер не настроен"}
    try:
        connected = mgr.test_connection(config)
        return {"connected": connected}
    except Exception as e:
        return {"connected": False, "error": str(e)}


# --- Analysis & Report endpoints ---


@router.post("/analyze/finding/{finding_id}", response_model=FindingAnalysisResponse)
def analyze_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):
    """Анализ конкретной находки через LLM."""
    vuln = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == finding_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Находка не найдена")

    llm = _get_llm_manager(db)
    analyzer = FindingAnalyzer(llm, db_session=db)
    controller = _get_controller(db)
    context = controller.build_session_context(vuln.program_id)

    raw = RawFinding(
        vulnerability_type=vuln.vulnerability_type,
        description=vuln.description,
        evidence=vuln.evidence,
        affected_asset_id=vuln.scan_id,
        raw_data={},
    )
    result = analyzer.analyze(raw, context)
    analyzer.save_analysis(vuln.id, result, db=db)

    return FindingAnalysisResponse(
        is_real_vulnerability=result.is_real_vulnerability,
        confidence=result.confidence,
        severity=result.severity,
        exploitability=result.exploitability,
        reasoning=result.reasoning,
    )


@router.post("/analyze/rules")
def analyze_rules(
    body: dict,
    db: Session = Depends(get_db),
):
    """Анализ правил программы через LLM."""
    program_id = body.get("program_id", "")
    question = body.get("question", "")
    if not program_id or not question:
        raise HTTPException(status_code=400, detail="Необходимо указать program_id и question")

    llm = _get_llm_manager(db)
    cm = ComplianceManager()
    analyzer = RuleAnalyzer(llm, cm)
    rules = cm.load_program_rules(program_id, db)
    answer = analyzer.answer_rule_question(question, rules)
    return {"answer": answer}


@router.post("/report/{vuln_id}")
def generate_ai_report(
    vuln_id: str,
    db: Session = Depends(get_db),
):
    """Генерация AI-отчёта."""
    vuln_record = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    if not vuln_record:
        raise HTTPException(status_code=404, detail="Уязвимость не найдена")

    from app.models.database import Program as ProgramDB
    from app.models.database import Scan as ScanDB
    program = db.query(ProgramDB).filter(ProgramDB.id == vuln_record.program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Программа не найдена")

    # Build Pydantic models from DB records
    from app.models.database import Asset as AssetDBModel
    from app.models.schemas import Asset as AssetSchema, AssetType

    scan_record = db.query(ScanDB).filter(ScanDB.id == vuln_record.scan_id).first()
    asset = None
    if scan_record:
        asset = db.query(AssetDBModel).filter(AssetDBModel.id == scan_record.asset_id).first()

    affected_asset = AssetSchema(
        id=asset.id if asset else "unknown",
        name=asset.name if asset else "unknown",
        asset_type=AssetType(asset.asset_type) if asset else AssetType.WEB_APPLICATION,
        target=asset.target if asset else "unknown",
        in_scope=True,
    )

    vulnerability = Vulnerability(
        id=vuln_record.id,
        scan_id=vuln_record.scan_id,
        program_id=vuln_record.program_id,
        vulnerability_type=vuln_record.vulnerability_type,
        severity=SeverityLevel(vuln_record.severity),
        description=vuln_record.description or "Уязвимость обнаружена автоматическим сканером",
        steps_to_reproduce=vuln_record.steps_to_reproduce or "1. Запустить автоматическое сканирование цели\n2. Наблюдать находку в результатах сканирования",
        evidence=vuln_record.evidence or "Обнаружено автоматическим сканером безопасности",
        affected_asset=affected_asset,
        impact_assessment=vuln_record.impact_assessment or "Потенциальное влияние на безопасность — требуется ручная проверка",
        remediation=vuln_record.remediation or "Проверить и устранить в соответствии с лучшими практиками безопасности",
        status=vuln_record.status,
        created_at=vuln_record.created_at,
    )

    parsed_program = ParsedProgram(
        id=program.id,
        name=program.name,
        platform=program.platform,
        assets=[],
        rules=[],
        reward_tiers=[],
        disclosure_requirements=program.disclosure_requirements or "",
        raw_text=program.raw_text or "",
        created_at=program.created_at,
    )

    llm = _get_llm_manager(db)
    gen = AIReportGenerator(llm)
    report = gen.generate(vulnerability, parsed_program)

    # Save report to DB so export endpoints work
    report_db = ReportDB(
        id=report.id,
        vulnerability_id=report.vulnerability_id,
        program_id=report.program_id,
        title=report.title,
        description=report.description,
        steps_to_reproduce=report.steps_to_reproduce,
        proof_of_concept=report.proof_of_concept,
        impact=report.impact,
        severity=report.severity.value if hasattr(report.severity, 'value') else report.severity,
        remediation=report.remediation,
        created_at=report.created_at,
        updated_at=report.updated_at,
    )
    db.add(report_db)
    db.commit()

    return report.model_dump()


@router.post("/report/{report_id}/improve")
def improve_report(
    report_id: str,
    request: ReportImproveRequest,
    db: Session = Depends(get_db),
):
    """Улучшение отчёта."""
    report_record = db.query(ReportDB).filter(ReportDB.id == report_id).first()
    if not report_record:
        raise HTTPException(status_code=404, detail="Отчёт не найден")

    report = Report(
        id=report_record.id,
        vulnerability_id=report_record.vulnerability_id,
        program_id=report_record.program_id,
        title=report_record.title,
        description=report_record.description,
        steps_to_reproduce=report_record.steps_to_reproduce,
        proof_of_concept=report_record.proof_of_concept,
        impact=report_record.impact,
        severity=SeverityLevel(report_record.severity),
        remediation=report_record.remediation,
        format_version="1.0",
        created_at=report_record.created_at,
        updated_at=report_record.updated_at,
    )

    llm = _get_llm_manager(db)
    gen = AIReportGenerator(llm)
    improved = gen.improve(report, request.instruction)
    return improved.model_dump()


@router.post("/recommendations/{program_id}")
def get_recommendations(
    program_id: str,
    db: Session = Depends(get_db),
):
    """Рекомендации следующих шагов."""
    controller = _get_controller(db)
    recs = controller.generate_recommendations(program_id)
    return {"recommendations": recs}


# =============================================================================
# AI-Driven Scan (Stage 2) endpoints
# =============================================================================

from app.models.ai_scan_schemas import (
    AIScanResult,
    ApprovalRequest,
    Stage2Status,
    StartStage2Request,
    Stage2StopResponse,
)
from app.models.database import Scan as ScanDB, AIScanState
from app.services.ai.ai_scanner import AIScanner
from app.services.audit_logger import AuditLogger


def _get_ai_scanner(db: Session) -> AIScanner:
    """Создаёт экземпляр AIScanner."""
    llm = _get_llm_manager(db)
    return AIScanner(
        llm_manager=llm,
        compliance_manager=ComplianceManager(),
        audit_logger=AuditLogger(),
        db=db,
    )


@router.post("/scans/{scan_id}/stage2", response_model=AIScanResult)
def start_stage2(
    scan_id: str,
    request: StartStage2Request = StartStage2Request(),
    db: Session = Depends(get_db),
):
    """Запуск Stage 2 (AI-Driven Scan) для существующего сканирования.

    Может быть запущен:
    - Автоматически после завершения Stage 1
    - Вручную для повторного AI-анализа существующих результатов
    """
    # Проверяем существование сканирования
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")

    # Проверяем, что Stage 1 завершён
    if scan.status not in ("completed", "running"):
        raise HTTPException(
            status_code=400,
            detail=f"Stage 1 должен быть завершён. Текущий статус: {scan.status}"
        )

    # Загружаем результаты Stage 1
    from app.models.database import VulnerabilityRecord
    stage1_vulns = db.query(VulnerabilityRecord).filter(
        VulnerabilityRecord.scan_id == scan_id
    ).all()

    stage1_results = [
        RawFinding(
            vulnerability_type=v.vulnerability_type,
            description=v.description,
            evidence=v.evidence,
            affected_asset_id=scan.asset_id,
            raw_data={"source": "stage1"},
        )
        for v in stage1_vulns
    ]

    # Загружаем правила и scope программы
    cm = ComplianceManager()
    rules = cm.load_program_rules(scan.program_id, db)
    scope = cm.load_program_scope(scan.program_id, db)

    # Определяем target URL
    from app.models.database import Asset as AssetDB
    asset = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
    target_url = asset.target if asset else ""

    # Определяем rate limit
    effective_rate = cm.get_effective_rate_limit(scan.program_id, db, request.rate_limit)

    # Запускаем Stage 2
    scanner = _get_ai_scanner(db)
    result = scanner.run_stage2(
        scan_id=scan_id,
        stage1_results=stage1_results,
        target_url=target_url,
        program_id=scan.program_id,
        rules=rules,
        scope=scope,
        supervised_mode=request.supervised_mode,
        max_iterations=request.max_iterations,
        max_requests=request.max_requests,
        rate_limit=effective_rate,
    )

    return result


@router.get("/scans/{scan_id}/stage2/status", response_model=Stage2Status)
def get_stage2_status(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Получение статуса Stage 2 сканирования."""
    state = db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
    if not state:
        raise HTTPException(status_code=404, detail="Stage 2 не запущен для этого сканирования")

    total_hypotheses = state.hypotheses_generated or 0
    tested = state.hypotheses_tested or 0
    percent = int((tested / total_hypotheses * 100) if total_hypotheses > 0 else 0)

    return Stage2Status(
        scan_id=scan_id,
        status=state.status,
        current_phase=state.current_phase,
        technologies_found=state.technologies_found or 0,
        hypotheses_generated=state.hypotheses_generated or 0,
        hypotheses_tested=state.hypotheses_tested or 0,
        requests_executed=state.requests_executed or 0,
        requests_blocked=state.requests_blocked or 0,
        findings_confirmed=state.findings_confirmed or 0,
        current_iteration=state.current_iteration or 0,
        max_iterations=state.max_iterations or 3,
        percent_complete=min(percent, 100),
        started_at=state.started_at,
        updated_at=state.updated_at,
    )


@router.post("/scans/{scan_id}/stage2/stop", response_model=Stage2StopResponse)
def stop_stage2(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Kill Switch — немедленная остановка Stage 2."""
    state = db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
    if not state:
        raise HTTPException(status_code=404, detail="Stage 2 не запущен для этого сканирования")

    if state.status not in ("running", "pending"):
        return Stage2StopResponse(
            scan_id=scan_id,
            stopped=False,
            message=f"Stage 2 уже завершён со статусом: {state.status}",
            requests_completed=state.requests_executed or 0,
            requests_pending=0,
        )

    # Устанавливаем флаг остановки
    state.stop_requested = True
    state.status = "cancelled"
    state.current_phase = "cancelled"
    db.commit()

    # Логируем в audit trail
    audit = AuditLogger()
    audit.log_ai_decision(
        scan_id=scan_id,
        entry_type="scan_cancelled",
        decision="cancelled",
        db=db,
        reasoning="Kill switch activated via API",
    )

    return Stage2StopResponse(
        scan_id=scan_id,
        stopped=True,
        message="Stage 2 остановлен",
        requests_completed=state.requests_executed or 0,
        requests_pending=0,
    )


@router.get("/scans/{scan_id}/stage2/approvals", response_model=list[ApprovalRequest])
def get_pending_approvals(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Получение списка запросов, ожидающих одобрения (Supervised Mode)."""
    # В текущей реализации supervised mode синхронный,
    # поэтому pending approvals хранятся в памяти scanner.
    # Для production нужна персистентная очередь.
    from app.models.database import AIRequestRecord

    pending = db.query(AIRequestRecord).filter(
        AIRequestRecord.status == "awaiting_approval",
    ).all()

    # Фильтруем по scan_id через hypothesis
    from app.models.database import AITestHypothesis
    result = []
    for req in pending:
        hyp = db.query(AITestHypothesis).filter(AITestHypothesis.id == req.hypothesis_id).first()
        if hyp and hyp.scan_id == scan_id:
            import json
            from app.models.ai_scan_schemas import AIRequest, TestHypothesis, HypothesisStatus

            hypothesis = TestHypothesis(
                id=hyp.id,
                scan_id=hyp.scan_id,
                description=hyp.description,
                rationale=hyp.rationale,
                target_url=hyp.target_url,
                vulnerability_type=hyp.vulnerability_type,
                severity_estimate=hyp.severity_estimate,
                iteration=hyp.iteration,
                status=HypothesisStatus(hyp.status),
            )

            ai_request = AIRequest(
                id=req.id,
                hypothesis_id=req.hypothesis_id,
                method=req.method,
                url=req.url,
                headers=json.loads(req.headers_json) if req.headers_json else {},
                body=req.body,
                expected_indicators=json.loads(req.expected_indicators_json) if req.expected_indicators_json else [],
            )

            result.append(ApprovalRequest(
                request_id=req.id,
                scan_id=scan_id,
                hypothesis=hypothesis,
                ai_request=ai_request,
                risks=[],
            ))

    return result


@router.post("/scans/{scan_id}/stage2/approvals/{request_id}")
def handle_approval(
    scan_id: str,
    request_id: str,
    approved: bool,
    reason: str | None = None,
    db: Session = Depends(get_db),
):
    """Одобрение или отклонение запроса в Supervised Mode."""
    from app.models.database import AIRequestRecord

    req = db.query(AIRequestRecord).filter(AIRequestRecord.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Запрос не найден")

    if req.status != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Запрос не ожидает одобрения. Статус: {req.status}"
        )

    if approved:
        req.status = "pending"  # Готов к выполнению
        req.user_approved = True
    else:
        req.status = "user_rejected"
        req.user_approved = False
        req.user_rejection_reason = reason

    db.commit()

    # Логируем в audit trail
    audit = AuditLogger()
    audit.log_ai_decision(
        scan_id=scan_id,
        entry_type="user_approved" if approved else "user_rejected",
        decision="approved" if approved else "rejected",
        db=db,
        request_id=request_id,
        reasoning=reason or ("User approved" if approved else "User rejected"),
    )

    return {
        "status": "ok",
        "request_id": request_id,
        "approved": approved,
    }


@router.get("/scans/{scan_id}/stage2/audit")
def export_ai_audit(
    scan_id: str,
    format: str = "json",
    db: Session = Depends(get_db),
):
    """Экспорт AI Audit Trail."""
    audit = AuditLogger()

    if format == "json":
        return audit.export_ai_trail(scan_id, db)
    else:
        # Возвращаем как dict для других форматов
        entries = audit.query_ai_trail(scan_id, db)
        return {"scan_id": scan_id, "entries": entries}


@router.get("/scans/{scan_id}/stage2/findings")
def get_stage2_findings(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Получение находок Stage 2."""
    from app.models.database import AIFindingRecord

    findings = db.query(AIFindingRecord).filter(
        AIFindingRecord.scan_id == scan_id
    ).all()

    return [
        {
            "id": f.id,
            "vulnerability_type": f.vulnerability_type,
            "severity": f.severity,
            "confidence": f.confidence,
            "description": f.description,
            "poc_request": f.poc_request,
            "poc_response": f.poc_response[:500] if f.poc_response else "",
            "reasoning": f.reasoning,
            "requires_manual_review": f.requires_manual_review,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]


@router.get("/scans/{scan_id}/stage2/technologies")
def get_stage2_technologies(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Получение идентифицированных технологий Stage 2."""
    from app.models.database import AITechnologyFingerprint
    import json

    techs = db.query(AITechnologyFingerprint).filter(
        AITechnologyFingerprint.scan_id == scan_id
    ).all()

    return [
        {
            "id": t.id,
            "name": t.name,
            "version": t.version,
            "category": t.category,
            "source": t.source,
            "confidence": t.confidence,
            "raw_evidence": t.raw_evidence,
            "known_cves": json.loads(t.known_cves_json) if t.known_cves_json else [],
        }
        for t in techs
    ]

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

"""API-эндпоинты для сканирования.

Содержит:
- POST /api/programs/{program_id}/scans — запуск сканирования
- GET /api/scans/{scan_id} — статус сканирования
- GET /api/scans/{scan_id}/progress — прогресс сканирования
- GET /api/programs/{program_id}/assets — активы программы

Требования: 4.1, 4.2, 2.1
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.database import (
    Program,
    Scan,
    User,
)
from app.models.database import Asset as AssetDB
from app.models.schemas import (
    Asset,
    AssetType,
    ScanConfig,
)
from app.services.compliance_manager import ComplianceManager
from app.services.scanner import Scanner
from app.services.scan_orchestrator import ScanOrchestrator

router = APIRouter(tags=["scans"])

# Singleton scanner instance for in-memory session tracking
_scanner = Scanner()


class StartScanRequest(BaseModel):
    """Запрос на запуск сканирования."""
    asset_id: str
    check_types: list[str] = []
    # AI-Driven Scan (Stage 2) настройки
    enable_ai_stage2: bool = False
    ai_supervised_mode: bool = False
    ai_max_iterations: int = 3
    ai_max_requests: int = 50
    ai_rate_limit: float = 5.0


def _asset_db_to_schema(row: AssetDB) -> Asset:
    """Конвертирует ORM Asset в Pydantic Asset."""
    return Asset(
        id=row.id,
        name=row.name,
        asset_type=AssetType(row.asset_type),
        target=row.target,
        in_scope=row.in_scope,
        notes=row.notes,
    )


def _scan_to_response(scan: Scan) -> dict:
    """Конвертирует ORM Scan в словарь для ответа API."""
    return {
        "id": scan.id,
        "program_id": scan.program_id,
        "asset_id": scan.asset_id,
        "status": scan.status,
        "current_stage": scan.current_stage,
        "percent_complete": scan.percent_complete,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings_count": len(scan.vulnerabilities) if scan.vulnerabilities else 0,
    }


@router.post("/api/programs/{program_id}/scans", status_code=201)
def start_scan(
    program_id: str,
    body: StartScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Запуск сканирования актива программы.

    Проверяет существование программы и актива, валидирует через ComplianceManager,
    запускает сканирование и возвращает прогресс.
    """
    # Проверяем программу
    program = db.query(Program).filter(Program.id == program_id).first()
    if program is None:
        raise HTTPException(status_code=404, detail="Программа не найдена")

    # Проверяем актив
    asset_row = db.query(AssetDB).filter(
        AssetDB.id == body.asset_id,
        AssetDB.program_id == program_id,
    ).first()
    if asset_row is None:
        raise HTTPException(status_code=404, detail="Актив не найден")

    asset = _asset_db_to_schema(asset_row)

    # Проверяем, что актив в scope
    if not asset.in_scope:
        raise HTTPException(status_code=403, detail="Актив вне области действия (out of scope)")

    scan_config = ScanConfig(
        asset_id=body.asset_id,
        program_id=program_id,
        check_types=body.check_types,
    )

    compliance_manager = ComplianceManager()
    rules = compliance_manager.load_program_rules(program_id, db)

    progress = _scanner.start_scan(asset, scan_config, compliance_manager, rules, db)

    return {
        "scan_id": progress.scan_id,
        "status": progress.status.value,
        "current_stage": progress.current_stage,
        "percent_complete": progress.percent_complete,
        "findings_count": progress.findings_count,
    }


@router.get("/api/scans/{scan_id}")
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Статус сканирования по ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    return _scan_to_response(scan)


@router.get("/api/scans/{scan_id}/progress")
def get_scan_progress(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Прогресс сканирования (из in-memory сессий или БД)."""
    # Сначала проверяем in-memory
    progress = _scanner.get_scan_progress(scan_id)
    if progress is not None:
        return {
            "scan_id": progress.scan_id,
            "status": progress.status.value,
            "current_stage": progress.current_stage,
            "percent_complete": progress.percent_complete,
            "findings_count": progress.findings_count,
        }

    # Fallback на БД
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "current_stage": scan.current_stage,
        "percent_complete": scan.percent_complete,
        "findings_count": len(scan.vulnerabilities) if scan.vulnerabilities else 0,
    }


@router.get("/api/programs/{program_id}/assets")
def list_program_assets(
    program_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Список активов программы."""
    program = db.query(Program).filter(Program.id == program_id).first()
    if program is None:
        raise HTTPException(status_code=404, detail="Программа не найдена")

    assets = db.query(AssetDB).filter(AssetDB.program_id == program_id).all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "asset_type": a.asset_type,
            "target": a.target,
            "in_scope": a.in_scope,
            "notes": a.notes,
        }
        for a in assets
    ]


_orchestrator = ScanOrchestrator()


@router.get("/api/scans/{scan_id}/plan")
def get_scan_plan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Предварительный план сканирования без запуска.

    Возвращает ScanPlan с указанием инструментов, порядка запуска
    и исключённых инструментов.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")

    asset_row = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
    if asset_row is None:
        raise HTTPException(status_code=404, detail="Актив не найден")

    asset = _asset_db_to_schema(asset_row)

    compliance_manager = ComplianceManager()
    rules = compliance_manager.load_program_rules(scan.program_id, db)

    # Convert ProgramRule ORM objects to Pydantic models for orchestrator
    from app.models.schemas import ProgramRule as ProgramRuleSchema
    rule_schemas = []
    for r in rules:
        rule_schemas.append(ProgramRuleSchema(
            id=r.id,
            description=r.description,
            is_allowed=r.is_allowed,
            category=r.category,
        ))

    plan = _orchestrator.create_scan_plan(asset, rule_schemas)

    return {
        "scan_id": plan.scan_id,
        "asset_type": plan.asset_type.value,
        "target": plan.target,
        "tools": plan.tools,
        "excluded_tools": [
            {"tool_name": et.tool_name, "reason": et.reason}
            for et in plan.excluded_tools
        ],
        "execution_order": plan.execution_order,
        "estimated_duration_minutes": plan.estimated_duration_minutes,
        "enable_ai_stage2": plan.enable_ai_stage2,
        "ai_supervised_mode": plan.ai_supervised_mode,
        "ai_max_iterations": plan.ai_max_iterations,
        "ai_max_requests": plan.ai_max_requests,
        "ai_rate_limit": plan.ai_rate_limit,
    }


class CreateScanPlanRequest(BaseModel):
    """Запрос на создание плана сканирования."""
    asset_id: str
    enable_ai_stage2: bool = False
    ai_supervised_mode: bool = False
    ai_max_iterations: int = 3
    ai_max_requests: int = 50
    ai_rate_limit: float = 5.0


@router.post("/api/programs/{program_id}/scan-plan")
def create_scan_plan(
    program_id: str,
    body: CreateScanPlanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Создаёт план сканирования с настройками Stage 2.

    Возвращает план без запуска сканирования.
    """
    # Проверяем программу
    program = db.query(Program).filter(Program.id == program_id).first()
    if program is None:
        raise HTTPException(status_code=404, detail="Программа не найдена")

    # Проверяем актив
    asset_row = db.query(AssetDB).filter(
        AssetDB.id == body.asset_id,
        AssetDB.program_id == program_id,
    ).first()
    if asset_row is None:
        raise HTTPException(status_code=404, detail="Актив не найден")

    asset = _asset_db_to_schema(asset_row)

    compliance_manager = ComplianceManager()
    rules = compliance_manager.load_program_rules(program_id, db)

    # Convert to Pydantic models
    from app.models.schemas import ProgramRule as ProgramRuleSchema
    rule_schemas = [
        ProgramRuleSchema(
            id=r.id,
            description=r.description,
            is_allowed=r.is_allowed,
            category=r.category,
        )
        for r in rules
    ]

    # Получаем effective rate limit
    effective_rate = compliance_manager.get_effective_rate_limit(
        program_id, db, body.ai_rate_limit
    )

    plan = _orchestrator.create_scan_plan(
        asset=asset,
        rules=rule_schemas,
        enable_ai_stage2=body.enable_ai_stage2,
        ai_supervised_mode=body.ai_supervised_mode,
        ai_max_iterations=body.ai_max_iterations,
        ai_max_requests=body.ai_max_requests,
        ai_rate_limit=effective_rate,
    )

    return {
        "scan_id": plan.scan_id,
        "asset_type": plan.asset_type.value,
        "target": plan.target,
        "tools": plan.tools,
        "excluded_tools": [
            {"tool_name": et.tool_name, "reason": et.reason}
            for et in plan.excluded_tools
        ],
        "execution_order": plan.execution_order,
        "estimated_duration_minutes": plan.estimated_duration_minutes,
        "enable_ai_stage2": plan.enable_ai_stage2,
        "ai_supervised_mode": plan.ai_supervised_mode,
        "ai_max_iterations": plan.ai_max_iterations,
        "ai_max_requests": plan.ai_max_requests,
        "ai_rate_limit": plan.ai_rate_limit,
    }

"""API-эндпоинты для уязвимостей и отчётов.

Содержит:
- GET /api/vulnerabilities — список уязвимостей с фильтрацией
- GET /api/vulnerabilities/{id} — детали уязвимости
- POST /api/vulnerabilities/{id}/report — генерация отчёта
- GET /api/reports/{id} — просмотр отчёта
- GET /api/reports/{id}/export — экспорт отчёта (md/pdf)

Требования: 5.3, 6.1, 6.3
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.database import (
    Program,
    Report as ReportDB,
    User,
    VulnerabilityRecord,
)
from app.models.database import Asset as AssetDB
from app.models.schemas import (
    ActionResult,
    Asset,
    AssetType,
    AuditEntry,
    ParsedProgram,
    ProgramRule,
    Report,
    RewardTier,
    SeverityLevel,
    Vulnerability,
)
from app.services.audit_logger import AuditLogger
from app.services.report_generator import ReportGenerator

router = APIRouter(tags=["vulnerabilities"])

_report_generator = ReportGenerator()
_audit_logger = AuditLogger()


def _vuln_row_to_schema(row: VulnerabilityRecord, asset_row: AssetDB) -> Vulnerability:
    """Конвертирует ORM VulnerabilityRecord в Pydantic Vulnerability."""
    return Vulnerability(
        id=row.id,
        scan_id=row.scan_id,
        program_id=row.program_id,
        vulnerability_type=row.vulnerability_type,
        severity=SeverityLevel(row.severity),
        description=row.description or "",
        steps_to_reproduce=row.steps_to_reproduce or "",
        evidence=row.evidence or "",
        affected_asset=Asset(
            id=asset_row.id,
            name=asset_row.name,
            asset_type=AssetType(asset_row.asset_type),
            target=asset_row.target,
            in_scope=asset_row.in_scope,
            notes=asset_row.notes,
        ),
        impact_assessment=row.impact_assessment or "",
        remediation=row.remediation or "",
        status=row.status,
        created_at=row.created_at or datetime.now(UTC),
    )


def _program_to_parsed(program: Program) -> ParsedProgram:
    """Конвертирует ORM Program в Pydantic ParsedProgram."""
    return ParsedProgram(
        id=program.id,
        name=program.name,
        platform=program.platform,
        assets=[
            Asset(
                id=a.id,
                name=a.name,
                asset_type=AssetType(a.asset_type),
                target=a.target,
                in_scope=a.in_scope,
                notes=a.notes,
            )
            for a in program.assets
        ],
        rules=[
            ProgramRule(
                id=r.id,
                description=r.description,
                is_allowed=r.is_allowed,
                category=r.category,
            )
            for r in program.rules
        ],
        reward_tiers=[
            RewardTier(
                severity=SeverityLevel(rt.severity),
                min_reward=rt.min_reward,
                max_reward=rt.max_reward,
                currency=rt.currency,
            )
            for rt in program.reward_tiers
        ],
        disclosure_requirements=program.disclosure_requirements,
        raw_text=program.raw_text,
        created_at=program.created_at or datetime.now(UTC),
        is_archived=program.is_archived,
    )


def _report_row_to_schema(row: ReportDB) -> Report:
    """Конвертирует ORM Report в Pydantic Report."""
    return Report(
        id=row.id,
        vulnerability_id=row.vulnerability_id,
        program_id=row.program_id,
        title=row.title,
        description=row.description,
        steps_to_reproduce=row.steps_to_reproduce,
        proof_of_concept=row.proof_of_concept,
        impact=row.impact,
        severity=SeverityLevel(row.severity),
        remediation=row.remediation,
        format_version="1.0",
        created_at=row.created_at or datetime.now(UTC),
        updated_at=row.updated_at or datetime.now(UTC),
    )


def _vuln_to_response(row: VulnerabilityRecord) -> dict:
    """Конвертирует ORM VulnerabilityRecord в словарь для ответа API."""
    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "program_id": row.program_id,
        "vulnerability_type": row.vulnerability_type,
        "severity": row.severity,
        "description": row.description,
        "steps_to_reproduce": row.steps_to_reproduce,
        "evidence": row.evidence,
        "impact_assessment": row.impact_assessment,
        "remediation": row.remediation,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _report_to_response(row: ReportDB) -> dict:
    """Конвертирует ORM Report в словарь для ответа API."""
    return {
        "id": row.id,
        "vulnerability_id": row.vulnerability_id,
        "program_id": row.program_id,
        "title": row.title,
        "description": row.description,
        "steps_to_reproduce": row.steps_to_reproduce,
        "proof_of_concept": row.proof_of_concept,
        "impact": row.impact,
        "severity": row.severity,
        "remediation": row.remediation,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("/api/vulnerabilities")
def list_vulnerabilities(
    severity: str | None = Query(None),
    asset_type: str | None = Query(None),
    status: str | None = Query(None),
    scan_id: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Список уязвимостей с фильтрацией по серьёзности, типу актива, статусу, scan_id."""
    from app.models.database import Scan

    q = db.query(VulnerabilityRecord)

    if severity is not None:
        q = q.filter(VulnerabilityRecord.severity == severity)
    if status is not None:
        q = q.filter(VulnerabilityRecord.status == status)
    if scan_id is not None:
        q = q.filter(VulnerabilityRecord.scan_id == scan_id)
    if asset_type is not None:
        q = q.join(Scan, VulnerabilityRecord.scan_id == Scan.id).join(
            AssetDB, Scan.asset_id == AssetDB.id
        ).filter(AssetDB.asset_type == asset_type)

    rows = q.all()
    return [_vuln_to_response(row) for row in rows]


@router.get("/api/vulnerabilities/{vuln_id}")
def get_vulnerability(
    vuln_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Детали уязвимости по ID."""
    row = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Уязвимость не найдена")
    return _vuln_to_response(row)


@router.post("/api/vulnerabilities/{vuln_id}/report", status_code=201)
def generate_report(
    vuln_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Генерация отчёта для уязвимости."""
    vuln_row = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    if vuln_row is None:
        raise HTTPException(status_code=404, detail="Уязвимость не найдена")

    # Получаем актив через scan
    from app.models.database import Scan
    scan = db.query(Scan).filter(Scan.id == vuln_row.scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")

    asset_row = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
    if asset_row is None:
        raise HTTPException(status_code=404, detail="Актив не найден")

    program = db.query(Program).filter(Program.id == vuln_row.program_id).first()
    if program is None:
        raise HTTPException(status_code=404, detail="Программа не найдена")

    vulnerability = _vuln_row_to_schema(vuln_row, asset_row)
    parsed_program = _program_to_parsed(program)

    report = _report_generator.generate(vulnerability, parsed_program)

    # Сохраняем отчёт в БД
    report_db = ReportDB(
        id=report.id,
        vulnerability_id=report.vulnerability_id,
        program_id=report.program_id,
        title=report.title,
        description=report.description,
        steps_to_reproduce=report.steps_to_reproduce,
        proof_of_concept=report.proof_of_concept,
        impact=report.impact,
        severity=report.severity.value,
        remediation=report.remediation,
        created_at=report.created_at,
        updated_at=report.updated_at,
    )
    db.add(report_db)
    db.commit()

    # Log report generation to audit
    _audit_logger.log(
        AuditEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            action_type="report_generation",
            target_asset=vuln_row.id,
            result=ActionResult.ALLOWED,
            program_id=vuln_row.program_id,
            rule_reference="",
            details=f"Сгенерирован отчёт: {report.title}",
        ),
        db,
    )

    return _report_to_response(report_db)


@router.get("/api/vuln-reports/{report_id}")
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Просмотр отчёта по уязвимости по ID."""
    row = db.query(ReportDB).filter(ReportDB.id == report_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    return _report_to_response(row)


@router.get("/api/vuln-reports/{report_id}/export")
def export_report(
    report_id: str,
    format: str = Query("md", pattern="^(md|pdf)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Экспорт отчёта в Markdown или PDF."""
    row = db.query(ReportDB).filter(ReportDB.id == report_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Отчёт не найден")

    report = _report_row_to_schema(row)

    if format == "md":
        md = _report_generator.export_markdown(report)
        return PlainTextResponse(content=md, media_type="text/markdown")
    else:
        pdf_bytes = _report_generator.export_pdf(report)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report-{report_id}.pdf"},
        )


@router.get("/api/scans/{scan_id}/summary-report")
def get_scan_summary_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Сводный отчёт по сканированию с группировкой по критичности."""
    from app.models.database import Scan
    from app.services.vulnerability_knowledge import get_vulnerability_info
    
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    # Получаем актив
    asset = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
    target_url = asset.target if asset else "Неизвестно"
    target_name = asset.name if asset else "Неизвестно"
    
    # Получаем все уязвимости
    vulns = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id == scan_id).all()
    
    # Группируем по серьёзности
    severity_order = ['critical', 'high', 'medium', 'low', 'informational']
    severity_labels = {
        'critical': 'Критические',
        'high': 'Высокие', 
        'medium': 'Средние',
        'low': 'Низкие',
        'informational': 'Информационные'
    }
    
    grouped = {s: [] for s in severity_order}
    for v in vulns:
        sev = v.severity if v.severity in severity_order else 'informational'
        
        # Получаем информацию из базы знаний
        info = get_vulnerability_info(v.vulnerability_type)
        title = info.title if info else v.vulnerability_type
        
        grouped[sev].append({
            'id': v.id,
            'type': v.vulnerability_type,
            'title': title,
            'description': v.description,
            'evidence': v.evidence,
            'steps_to_reproduce': v.steps_to_reproduce,
            'impact': v.impact_assessment,
            'remediation': v.remediation,
        })
    
    # Статистика
    stats = {
        'total': len(vulns),
        'critical': len(grouped['critical']),
        'high': len(grouped['high']),
        'medium': len(grouped['medium']),
        'low': len(grouped['low']),
        'informational': len(grouped['informational']),
    }
    
    return {
        'scan_id': scan_id,
        'target_url': target_url,
        'target_name': target_name,
        'scan_date': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'status': scan.status,
        'stats': stats,
        'vulnerabilities': {
            severity: {
                'label': severity_labels[severity],
                'count': len(items),
                'items': items
            }
            for severity, items in grouped.items()
            if items  # Только непустые группы
        }
    }

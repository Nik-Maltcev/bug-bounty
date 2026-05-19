"""API-эндпоинты для управления отчётами.

Содержит:
- GET /api/reports — список всех отчётов
- GET /api/reports/{id} — получить отчёт
- PUT /api/reports/{id} — обновить отчёт (редактирование)
- POST /api/reports/{id}/pdf — скачать PDF
- DELETE /api/reports/{id} — удалить отчёт
"""

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.database import ScanReport, Scan, User
from app.models.database import Asset as AssetDB

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportUpdate(BaseModel):
    """Схема обновления отчёта."""
    title: str | None = None
    executive_summary: str | None = None
    findings_summary: str | None = None
    risk_assessment: str | None = None
    compliance_notes: str | None = None
    recommendations: str | None = None
    conclusion: str | None = None
    status: str | None = None


def _report_to_response(report: ScanReport, db: Session) -> dict:
    """Конвертирует ORM ScanReport в словарь."""
    # Получаем инфо о скане
    scan = db.query(Scan).filter(Scan.id == report.scan_id).first()
    target_url = ""
    findings_count = 0
    if scan:
        findings_count = len(scan.vulnerabilities) if scan.vulnerabilities else 0
        if scan.asset_id:
            asset = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
            if asset:
                target_url = asset.target

    return {
        "id": report.id,
        "scan_id": report.scan_id,
        "report_type": report.report_type if hasattr(report, 'report_type') and report.report_type else "full",
        "title": report.title,
        "target_url": target_url or report.target_url,
        "category": report.category,
        "executive_summary": report.executive_summary,
        "findings_summary": report.findings_summary,
        "risk_assessment": report.risk_assessment,
        "compliance_notes": report.compliance_notes,
        "recommendations": report.recommendations,
        "conclusion": report.conclusion,
        "status": report.status,
        "findings_count": findings_count,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "updated_at": report.updated_at.isoformat() if report.updated_at else None,
    }


@router.get("")
def list_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """Список всех отчётов."""
    reports = db.query(ScanReport).order_by(ScanReport.created_at.desc()).offset(offset).limit(limit).all()
    return [_report_to_response(r, db) for r in reports]


@router.get("/{report_id}")
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Получить отчёт по ID."""
    report = db.query(ScanReport).filter(ScanReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    return _report_to_response(report, db)


@router.put("/{report_id}")
def update_report(
    report_id: str,
    body: ReportUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Обновить отчёт (редактирование)."""
    report = db.query(ScanReport).filter(ScanReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    
    update_data = body.model_dump(exclude_none=True)
    for field, value in update_data.items():
        setattr(report, field, value)
    
    report.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(report)
    
    return _report_to_response(report, db)


@router.delete("/{report_id}")
def delete_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Удалить отчёт."""
    report = db.query(ScanReport).filter(ScanReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    
    db.delete(report)
    db.commit()
    return {"status": "deleted"}


@router.post("/{report_id}/pdf")
def download_report_pdf(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Скачать PDF-отчёт из редактируемого контента."""
    report = db.query(ScanReport).filter(ScanReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    
    try:
        from app.services.report_pdf_generator import generate_report_pdf
        pdf_bytes = generate_report_pdf(report)
        
        filename = f"report_{report.target_url.replace('https://', '').replace('http://', '').replace('/', '_')}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error("PDF generation error: %s", e)
        raise HTTPException(status_code=500, detail=f"Ошибка генерации PDF: {str(e)}")

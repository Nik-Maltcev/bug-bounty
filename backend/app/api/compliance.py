"""API-эндпоинт статуса соответствия правилам программы.

Содержит:
- GET /api/compliance/{program_id} — сводка по соблюдению правил

Требования: 3.4
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.database import User
from app.models.schemas import ComplianceSummary
from app.services.compliance_manager import ComplianceManager

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get("/{program_id}", response_model=ComplianceSummary)
def get_compliance_summary(
    program_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ComplianceSummary:
    """Сводка по соблюдению правил программы.

    Возвращает общее количество действий, разрешённых и заблокированных,
    а также группированные причины блокировок.
    """
    manager = ComplianceManager()
    return manager.get_compliance_summary(program_id, db)

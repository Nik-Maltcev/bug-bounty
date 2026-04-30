"""API-эндпоинты для слоя безопасности.

Содержит:
- POST /api/safety/kill — активация Kill Switch
- GET /api/safety/status — состояние ограничений безопасности
"""

from fastapi import APIRouter, Depends

from app.core.auth import get_current_user
from app.models.database import User
from app.services.safety_layer import SafetyLayer

router = APIRouter(tags=["safety"])

_safety_layer = SafetyLayer()


@router.post("/api/safety/kill")
def activate_kill_switch(
    current_user: User = Depends(get_current_user),
) -> dict:
    """Активация Kill Switch — немедленная остановка всех процессов."""
    result = _safety_layer.activate_kill_switch()
    return {
        "terminated_processes": result.terminated_processes,
        "cancelled_scans": result.cancelled_scans,
        "timestamp": result.timestamp.isoformat(),
    }


@router.get("/api/safety/status")
def get_safety_status(
    current_user: User = Depends(get_current_user),
) -> dict:
    """Текущее состояние ограничений безопасности."""
    status = _safety_layer.get_safety_status()
    return {
        "kill_switch_active": status.kill_switch_active,
        "active_processes_count": status.active_processes_count,
        "rate_limit_rps": status.rate_limit_rps,
        "active_scans": status.active_scans,
    }

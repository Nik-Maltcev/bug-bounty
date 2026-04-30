"""API-эндпоинты для управления инструментами безопасности.

Содержит:
- GET /api/tools/status — статус всех инструментов
- POST /api/tools/{tool_name}/install — установка инструмента
"""

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import get_current_user
from app.models.database import User
from app.services.tool_manager import ToolManager

router = APIRouter(tags=["tools"])

_tool_manager = ToolManager()


@router.get("/api/tools/status")
def get_tools_status(
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Статус всех поддерживаемых инструментов безопасности."""
    tools = _tool_manager.discover_all()
    return [
        {
            "name": t.name,
            "status": t.status.value,
            "version": t.version,
            "min_version": t.min_version,
            "path": t.path,
            "install_command": t.install_command,
            "asset_types": [at.value for at in t.asset_types],
        }
        for t in tools
    ]


@router.post("/api/tools/{tool_name}/install", status_code=202)
def install_tool(
    tool_name: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Установка инструмента безопасности."""
    try:
        info = _tool_manager.install_tool(tool_name)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "name": info.name,
        "status": info.status.value,
        "version": info.version,
        "message": f"Установка инструмента '{tool_name}' завершена",
    }

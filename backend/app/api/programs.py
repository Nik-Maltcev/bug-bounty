"""API-эндпоинты управления программами bug bounty.

Содержит:
- POST /api/programs — импорт программы (парсинг + сохранение)
- GET /api/programs — список программ
- GET /api/programs/{id} — детали программы
- PUT /api/programs/{id} — обновление программы
- PATCH /api/programs/{id}/archive — архивирование программы

Требования: 1.1, 1.2, 8.1
"""

import uuid as _uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.database import (
    Asset as AssetDB,
    Program,
    ProgramRule as ProgramRuleDB,
    RewardTier as RewardTierDB,
    User,
)
from app.models.schemas import ActionResult, AuditEntry, ParsedProgram, ProgramSource
from app.services.audit_logger import AuditLogger
from app.services.rules_parser import RulesParser

router = APIRouter(prefix="/api/programs", tags=["programs"])

_audit_logger = AuditLogger()


class ProgramUpdate(BaseModel):
    """Схема обновления программы."""
    name: str | None = None
    platform: str | None = None
    disclosure_requirements: str | None = None


def _program_to_response(program: Program) -> dict:
    """Конвертирует ORM-модель Program в словарь для ответа API."""
    return {
        "id": program.id,
        "name": program.name,
        "platform": program.platform,
        "disclosure_requirements": program.disclosure_requirements,
        "raw_text": program.raw_text,
        "created_at": program.created_at.isoformat(),
        "is_archived": program.is_archived,
        "assets": [
            {
                "id": a.id,
                "name": a.name,
                "asset_type": a.asset_type,
                "target": a.target,
                "in_scope": a.in_scope,
                "notes": a.notes,
            }
            for a in program.assets
        ],
        "rules": [
            {
                "id": r.id,
                "description": r.description,
                "is_allowed": r.is_allowed,
                "category": r.category,
            }
            for r in program.rules
        ],
        "reward_tiers": [
            {
                "id": rt.id,
                "severity": rt.severity,
                "min_reward": rt.min_reward,
                "max_reward": rt.max_reward,
                "currency": rt.currency,
            }
            for rt in program.reward_tiers
        ],
    }


@router.post("", status_code=201)
async def import_program(
    source: ProgramSource,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Импорт программы: парсинг текста/URL и сохранение в БД.

    Raises:
        ParseError: если не удалось распарсить источник
    """
    parser = RulesParser()
    parsed: ParsedProgram = await parser.parse(source)

    # Сохранение Program
    program = Program(
        id=parsed.id,
        name=parsed.name,
        platform=parsed.platform,
        disclosure_requirements=parsed.disclosure_requirements,
        raw_text=parsed.raw_text,
        created_at=parsed.created_at,
        is_archived=False,
    )
    db.add(program)

    # Сохранение Assets
    for asset in parsed.assets:
        db.add(AssetDB(
            id=asset.id,
            program_id=program.id,
            name=asset.name,
            asset_type=asset.asset_type.value,
            target=asset.target,
            in_scope=asset.in_scope,
            notes=asset.notes,
        ))

    # Сохранение Rules
    for rule in parsed.rules:
        db.add(ProgramRuleDB(
            id=rule.id,
            program_id=program.id,
            description=rule.description,
            is_allowed=rule.is_allowed,
            category=rule.category,
        ))

    # Сохранение RewardTiers
    for tier in parsed.reward_tiers:
        db.add(RewardTierDB(
            id=str(_uuid.uuid4()),
            program_id=program.id,
            severity=tier.severity.value,
            min_reward=tier.min_reward,
            max_reward=tier.max_reward,
            currency=tier.currency,
        ))

    db.commit()
    db.refresh(program)

    # Log program import to audit
    _audit_logger.log(
        AuditEntry(
            id=str(_uuid.uuid4()),
            timestamp=datetime.now(UTC),
            action_type="program_import",
            target_asset=program.id,
            result=ActionResult.ALLOWED,
            program_id=program.id,
            rule_reference="",
            details=f"Импортирована программа: {program.name}",
        ),
        db,
    )

    return _program_to_response(program)


@router.get("")
def list_programs(
    archived: bool | None = Query(None, description="Фильтр по архивным программам"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Список программ с опциональной фильтрацией по архивности."""
    query = db.query(Program)
    if archived is not None:
        query = query.filter(Program.is_archived == archived)
    programs = query.all()
    return [_program_to_response(p) for p in programs]


@router.get("/{program_id}")
def get_program(
    program_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Детали программы с активами, правилами и вознаграждениями."""
    program = db.query(Program).filter(Program.id == program_id).first()
    if program is None:
        raise HTTPException(status_code=404, detail="Программа не найдена")
    return _program_to_response(program)


@router.put("/{program_id}")
def update_program(
    program_id: str,
    body: ProgramUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Обновление метаданных программы (name, platform, disclosure_requirements)."""
    program = db.query(Program).filter(Program.id == program_id).first()
    if program is None:
        raise HTTPException(status_code=404, detail="Программа не найдена")

    if body.name is not None:
        program.name = body.name
    if body.platform is not None:
        program.platform = body.platform
    if body.disclosure_requirements is not None:
        program.disclosure_requirements = body.disclosure_requirements

    db.commit()
    db.refresh(program)
    return _program_to_response(program)


@router.patch("/{program_id}/archive")
def archive_program(
    program_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Архивирование программы (is_archived=True)."""
    program = db.query(Program).filter(Program.id == program_id).first()
    if program is None:
        raise HTTPException(status_code=404, detail="Программа не найдена")

    program.is_archived = True
    db.commit()
    db.refresh(program)

    # Log archive action to audit
    _audit_logger.log(
        AuditEntry(
            id=str(_uuid.uuid4()),
            timestamp=datetime.now(UTC),
            action_type="program_archive",
            target_asset=program.id,
            result=ActionResult.ALLOWED,
            program_id=program.id,
            rule_reference="",
            details=f"Программа архивирована: {program.name}",
        ),
        db,
    )

    return _program_to_response(program)

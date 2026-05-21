"""API-эндпоинты CRM — управление клиентами.

Содержит:
- GET /api/clients — список клиентов (с фильтрами и поиском)
- POST /api/clients — создать клиента
- POST /api/clients/bulk — массовый импорт клиентов
- GET /api/clients/{id} — получить клиента
- PUT /api/clients/{id} — обновить клиента
- PATCH /api/clients/{id}/status — изменить статус
- DELETE /api/clients/{id} — удалить клиента
- GET /api/clients/export/csv — экспорт в CSV
"""

import csv
import io
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from fastapi import UploadFile, File
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.models.database import Client, User

router = APIRouter(prefix="/api/clients", tags=["clients"])


class ClientCreate(BaseModel):
    """Создание клиента."""
    company_name: str
    contact_name: str = ""
    email: str = ""
    phone: str = ""
    website: str = ""
    category: str = ""
    status: str = "new"
    notes: str = ""


class ClientUpdate(BaseModel):
    """Обновление клиента."""
    company_name: str | None = None
    contact_name: str | None = None
    email: str | None = None
    phone: str | None = None
    website: str | None = None
    category: str | None = None
    status: str | None = None
    notes: str | None = None
    scan_id: str | None = None


class ClientBulkCreate(BaseModel):
    """Массовый импорт клиентов."""
    clients: list[ClientCreate]


class ScanByCategoryRequest(BaseModel):
    """Запуск сканов для всех клиентов категории."""
    category: str
    auto_ai_analysis: bool = True


class StatusUpdate(BaseModel):
    """Изменение статуса."""
    status: str


def _client_to_response(client: Client) -> dict:
    return {
        "id": client.id,
        "company_name": client.company_name,
        "contact_name": client.contact_name,
        "email": client.email,
        "phone": client.phone,
        "website": client.website,
        "category": client.category,
        "status": client.status,
        "notes": client.notes,
        "scan_id": client.scan_id,
        "created_at": client.created_at.isoformat() if client.created_at else None,
        "updated_at": client.updated_at.isoformat() if client.updated_at else None,
    }


@router.get("")
def list_clients(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    search: str = "",
    status: str = "",
    category: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Список клиентов с фильтрами и поиском."""
    query = db.query(Client)
    
    if search:
        search_filter = f"%{search}%"
        query = query.filter(or_(
            Client.company_name.ilike(search_filter),
            Client.contact_name.ilike(search_filter),
            Client.email.ilike(search_filter),
            Client.website.ilike(search_filter),
        ))
    
    if status:
        query = query.filter(Client.status == status)
    
    if category:
        query = query.filter(Client.category == category)
    
    total = query.count()
    clients = query.order_by(Client.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "clients": [_client_to_response(c) for c in clients],
    }


@router.post("", status_code=201)
def create_client(
    body: ClientCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Создать клиента."""
    # Нормализуем категорию (не капсом)
    category = body.category.strip()
    if category.isupper():
        category = category.capitalize()
    
    client = Client(
        id=str(uuid.uuid4()),
        company_name=body.company_name,
        contact_name=body.contact_name,
        email=body.email,
        phone=body.phone,
        website=body.website,
        category=category,
        status=body.status,
        notes=body.notes,
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    return _client_to_response(client)


@router.post("/bulk", status_code=201)
def bulk_create_clients(
    body: ClientBulkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Массовый импорт клиентов."""
    if len(body.clients) > 500:
        raise HTTPException(status_code=400, detail="Максимум 500 клиентов за раз")
    
    created = 0
    for c in body.clients:
        # Нормализуем категорию
        category = c.category.strip() if c.category else ""
        if category.isupper():
            category = category.capitalize()
        
        client = Client(
            id=str(uuid.uuid4()),
            company_name=c.company_name,
            contact_name=c.contact_name,
            email=c.email,
            phone=c.phone,
            website=c.website,
            category=category,
            status=c.status,
            notes=c.notes,
        )
        db.add(client)
        created += 1
    
    db.commit()
    return {"created": created}


@router.post("/import-csv", status_code=201)
async def import_csv(
    file: UploadFile,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Импорт клиентов из CSV файла (формат: Категория, #, Компания, Сайт, Примечание)."""
    content = await file.read()
    text = content.decode("utf-8-sig")
    
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    
    if not rows:
        raise HTTPException(status_code=400, detail="Пустой файл")
    
    # Пропускаем заголовок
    data_rows = rows[1:] if rows[0][0].lower().startswith("категор") else rows
    
    created = 0
    for row in data_rows:
        if len(row) < 4:
            continue
        
        category_raw = row[0].strip()
        company = row[2].strip() if len(row) > 2 else ""
        website = row[3].strip() if len(row) > 3 else ""
        notes = row[4].strip() if len(row) > 4 else ""
        
        if not company and not website:
            continue
        
        # Нормализуем категорию
        # "Банки (без Сбербанка)" -> "Банки"
        category = category_raw.split("(")[0].strip()
        if category.isupper():
            category = category.capitalize()
        
        client = Client(
            id=str(uuid.uuid4()),
            company_name=company or website,
            website=website,
            category=category,
            notes=notes,
            status="new",
        )
        db.add(client)
        created += 1
    
    db.commit()
    return {"created": created, "filename": file.filename}


@router.get("/export/csv")
def export_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    status: str = "",
    category: str = "",
):
    """Экспорт клиентов в CSV."""
    query = db.query(Client)
    if status:
        query = query.filter(Client.status == status)
    if category:
        query = query.filter(Client.category == category)
    
    clients = query.order_by(Client.created_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Компания", "Контакт", "Email", "Телефон", "Сайт", "Категория", "Статус", "Дата"])
    
    for c in clients:
        writer.writerow([
            c.company_name, c.contact_name, c.email, c.phone,
            c.website, c.category, c.status,
            c.created_at.strftime("%d.%m.%Y") if c.created_at else "",
        ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=clients.csv"},
    )


@router.get("/{client_id}")
def get_client(
    client_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Получить клиента."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return _client_to_response(client)


@router.put("/{client_id}")
def update_client(
    client_id: str,
    body: ClientUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Обновить клиента."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    
    update_data = body.model_dump(exclude_none=True)
    for field, value in update_data.items():
        setattr(client, field, value)
    
    client.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(client)
    return _client_to_response(client)


@router.patch("/{client_id}/status")
def update_status(
    client_id: str,
    body: StatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Изменить статус клиента."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    
    client.status = body.status
    client.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(client)
    return _client_to_response(client)


@router.delete("/{client_id}")
def delete_client(
    client_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Удалить клиента."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    
    db.delete(client)
    db.commit()
    return {"status": "deleted"}



@router.post("/scan-category")
def scan_by_category(
    body: ScanByCategoryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Запустить массовое сканирование всех клиентов в категории."""
    clients = db.query(Client).filter(Client.category == body.category).all()
    
    if not clients:
        raise HTTPException(status_code=404, detail=f"Нет клиентов в категории '{body.category}'")
    
    # Собираем сайты
    targets = []
    for c in clients:
        if c.website:
            url = c.website.strip()
            if not url.startswith('http'):
                url = 'https://' + url
            targets.append(url)
    
    if not targets:
        raise HTTPException(status_code=400, detail="Нет сайтов для сканирования в этой категории")
    
    # Вызываем batch scan
    from app.api.scans import BatchScanRequest, batch_scan
    
    batch_body = BatchScanRequest(
        targets=targets,
        category=body.category,
        scan_type="web",
        auto_ai_analysis=body.auto_ai_analysis,
    )
    
    result = batch_scan(batch_body, db, current_user)
    
    # Обновляем статус клиентов
    for c in clients:
        if c.website:
            c.status = "scanning"
    db.commit()
    
    return {
        "category": body.category,
        "clients_count": len(clients),
        "scans_started": result["started"],
        "errors": result["errors"],
    }


@router.get("/categories")
def list_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Список всех категорий с количеством клиентов."""
    from sqlalchemy import func
    
    results = db.query(
        Client.category, func.count(Client.id)
    ).filter(Client.category != "").group_by(Client.category).all()
    
    return [{"category": cat, "count": count} for cat, count in results]

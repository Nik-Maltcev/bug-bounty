"""API-эндпоинты для сканирования.

Содержит:
- POST /api/programs/{program_id}/scans — запуск сканирования
- POST /api/scans/quick — быстрое сканирование по URL
- GET /api/scans — список всех сканирований
- GET /api/scans/{scan_id} — статус сканирования
- GET /api/scans/{scan_id}/progress — прогресс сканирования
- GET /api/programs/{program_id}/assets — активы программы

Требования: 4.1, 4.2, 2.1
"""

import json
import logging
import uuid
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

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
        "target_url": scan.target_url if hasattr(scan, 'target_url') else None,
        "category": scan.category if hasattr(scan, 'category') else "",
    }


class QuickScanRequest(BaseModel):
    """Запрос на быстрое сканирование по URL."""
    target_url: str
    scan_type: str = "web"  # web, api, full
    category: str = ""  # отрасль клиента


class BatchScanRequest(BaseModel):
    """Запрос на пакетное сканирование списка сайтов."""
    targets: list[str]  # список URL
    category: str = ""  # отрасль для всех сканов
    scan_type: str = "web"
    auto_ai_analysis: bool = True  # автоматически запускать AI-анализ


@router.post("/api/scans/quick", status_code=201)
def quick_scan(
    body: QuickScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Быстрое сканирование по URL без создания программы.
    
    Создаёт временную программу и актив, запускает сканирование.
    """
    # Валидация URL
    try:
        parsed = urlparse(body.target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
        target_url = body.target_url
        domain = parsed.netloc
    except Exception:
        raise HTTPException(status_code=400, detail="Некорректный URL")

    # Создаём временную программу
    program_id = str(uuid.uuid4())
    program = Program(
        id=program_id,
        name=f"Quick Scan: {domain}",
        platform="quick_scan",
        raw_text=f"Quick scan target: {target_url}",
        is_archived=False,
    )
    db.add(program)

    # Создаём актив
    asset_id = str(uuid.uuid4())
    asset_type = "web_application"  # Всегда web_application
    asset_db = AssetDB(
        id=asset_id,
        program_id=program_id,
        name=domain,
        asset_type=asset_type,
        target=target_url,
        in_scope=True,
        notes=f"Quick scan target: {target_url}",
    )
    db.add(asset_db)
    db.commit()

    asset = Asset(
        id=asset_id,
        name=domain,
        asset_type=AssetType(asset_type),
        target=target_url,
        in_scope=True,
        notes=f"Quick scan target: {target_url}",
    )

    scan_config = ScanConfig(
        asset_id=asset_id,
        program_id=program_id,
        check_types=[],
    )

    compliance_manager = ComplianceManager()
    rules = compliance_manager.load_program_rules(program_id, db)

    progress = _scanner.start_scan(asset, scan_config, compliance_manager, rules, db)

    # Сохраняем категорию если указана
    if body.category:
        scan_record = db.query(Scan).filter(Scan.id == progress.scan_id).first()
        if scan_record:
            scan_record.category = body.category
            db.commit()

    return {
        "scan_id": progress.scan_id,
        "status": progress.status.value,
        "current_stage": progress.current_stage,
        "percent_complete": progress.percent_complete,
        "findings_count": progress.findings_count,
        "target_url": target_url,
    }


def _run_stage2_and_reports(scan_id: str, item: dict, category: str, db: Session):
    """Запускает полный AI Stage 2, затем генерирует 3 отчёта."""
    import os
    from app.models.database import VulnerabilityRecord, AIScanState
    from app.models.schemas import RawFinding
    from app.services.ai.ai_scanner import AIScanner
    from app.services.ai.llm_provider_manager import LLMProviderManager
    from app.models.ai_schemas import LLMConfig, ProviderType
    
    logger.info("Starting Stage 2 for scan %s (%s)", scan_id, item['target_url'])
    
    # Получаем уязвимости Stage 1
    vulns = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id == scan_id).all()
    if not vulns:
        logger.info("No vulns for Stage 2, skipping: %s", scan_id)
        return
    
    # Проверяем API ключ
    deepseek_key = os.environ.get("DEEPSEEK_API_KEY")
    if not deepseek_key:
        logger.warning("No DEEPSEEK_API_KEY, skipping Stage 2")
        _run_ai_and_create_report(scan_id, category, db)
        return
    
    # Конвертируем уязвимости в RawFinding
    stage1_results = []
    for v in vulns:
        raw_data = {}
        if v.raw_data_json:
            try:
                raw_data = json.loads(v.raw_data_json)
            except Exception:
                pass
        raw_data.update({"severity": v.severity, "source": "stage1_scan"})
        
        stage1_results.append(RawFinding(
            vulnerability_type=v.vulnerability_type,
            description=v.description or "",
            evidence=v.evidence or "",
            affected_asset_id=item['asset_id'],
            raw_data=raw_data,
        ))
    
    # Настраиваем LLM
    llm_config = LLMConfig(
        provider=ProviderType.DEEPSEEK,
        api_key=deepseek_key,
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        temperature=0.3,
    )
    
    llm_manager = LLMProviderManager(db_session=db)
    llm_manager.save_provider_config(llm_config)
    
    # Запускаем Stage 2
    ai_scanner = AIScanner(llm_manager=llm_manager, db=db)
    
    try:
        result = ai_scanner.run_stage2(
            scan_id=scan_id,
            stage1_results=stage1_results,
            target_url=item['target_url'],
            program_id=item['program_id'],
            supervised_mode=False,
            max_iterations=3,
            max_requests=30,
            rate_limit=3.0,
        )
        logger.info("Stage 2 completed for %s: %s findings", scan_id, len(result.findings))
    except Exception as e:
        logger.error("Stage 2 execution error for %s: %s", scan_id, e)
    
    # Генерируем 3 отчёта (на основе всех уязвимостей — Stage 1 + Stage 2)
    _run_ai_and_create_report(scan_id, category, db)


def _run_ai_and_create_report(scan_id: str, category: str, db: Session):
    """Запускает AI-анализ и создаёт 3 уровня отчётов: full, medium, demo."""
    import os
    import httpx as httpx_client
    
    from app.models.database import ScanReport, VulnerabilityRecord
    
    logger.info("Starting AI report generation for scan %s", scan_id)
    
    # Получаем уязвимости скана
    vulns = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id == scan_id).all()
    
    if not vulns:
        logger.info("No vulnerabilities found for scan %s, skipping AI report", scan_id)
        return
    
    # Получаем скан и target
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    target_url = ""
    if scan and scan.asset_id:
        asset = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
        if asset:
            target_url = asset.target
    
    # Формируем данные
    vuln_details = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    
    for v in vulns:
        severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        vuln_details.append({
            "type": v.vulnerability_type,
            "severity": v.severity,
            "description": v.description[:300],
            "remediation": v.remediation[:200] if v.remediation else "",
        })
    
    vuln_text_full = "\n".join([
        f"- [{v['severity'].upper()}] {v['type']}: {v['description']}" 
        for v in vuln_details[:30]
    ])
    
    # AI-генерация полного отчёта
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        logger.warning("No DEEPSEEK_API_KEY, creating basic reports")
        _create_basic_reports(scan_id, target_url, category, vulns, vuln_text_full, severity_counts, db)
        return
    
    prompt = f"""Ты — эксперт по кибербезопасности. Составь ПОЛНЫЙ профессиональный отчёт на русском языке.

Цель: {target_url}
Отрасль: {category or 'общая'}
Найдено уязвимостей: {len(vulns)} (критических: {severity_counts['critical']}, высоких: {severity_counts['high']}, средних: {severity_counts['medium']}, низких: {severity_counts['low']})

Уязвимости:
{vuln_text_full}

Напиши ПОЛНЫЙ отчёт в формате JSON:
{{
  "executive_summary": "Резюме для руководства (5-7 предложений, с цифрами рисков в рублях)",
  "findings_detailed": "Детальное описание КАЖДОЙ найденной уязвимости: что это, где найдено, как эксплуатировать, какой риск",
  "risk_assessment": "Оценка рисков для бизнеса: потенциальные потери в рублях, сценарии атак, влияние на репутацию",
  "compliance_notes": "Конкретные нарушения 152-ФЗ, 187-ФЗ, PCI DSS с указанием статей и штрафов",
  "recommendations": "ПОШАГОВЫЕ инструкции по устранению каждой уязвимости: конкретные команды, конфиги, код",
  "conclusion": "Заключение: общая оценка, приоритеты исправления, сроки"
}}

Отвечай ТОЛЬКО JSON, без markdown."""

    try:
        response = httpx_client.post(
            "https://api.deepseek.com/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 4000,
            },
            timeout=120.0,
        )
        
        ai_text = response.json()["choices"][0]["message"]["content"]
        ai_text = ai_text.strip()
        if ai_text.startswith("```"):
            ai_text = ai_text.split("\n", 1)[1] if "\n" in ai_text else ai_text[3:]
            if ai_text.endswith("```"):
                ai_text = ai_text[:-3]
        
        import json as json_mod
        ai_data = json_mod.loads(ai_text)
        
        # === 1. ПОЛНЫЙ ОТЧЁТ ===
        full_report = ScanReport(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            report_type="full",
            title=f"[Полный] {target_url}",
            target_url=target_url,
            category=category,
            executive_summary=ai_data.get("executive_summary", ""),
            findings_summary=ai_data.get("findings_detailed", vuln_text_full),
            risk_assessment=ai_data.get("risk_assessment", ""),
            compliance_notes=ai_data.get("compliance_notes", ""),
            recommendations=ai_data.get("recommendations", ""),
            conclusion=ai_data.get("conclusion", ""),
            status="draft",
        )
        db.add(full_report)
        
        # === 2. СРЕДНИЙ ОТЧЁТ (без рекомендаций по устранению) ===
        medium_findings = vuln_text_full  # Уязвимости видны
        medium_recommendations = "⚠️ Детальные инструкции по устранению доступны в полной версии отчёта.\n\nДля получения пошаговых рекомендаций по исправлению каждой уязвимости обратитесь к нашим специалистам."
        
        medium_report = ScanReport(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            report_type="medium",
            title=f"[Технический] {target_url}",
            target_url=target_url,
            category=category,
            executive_summary=ai_data.get("executive_summary", ""),
            findings_summary=ai_data.get("findings_detailed", vuln_text_full),
            risk_assessment=ai_data.get("risk_assessment", ""),
            compliance_notes=ai_data.get("compliance_notes", ""),
            recommendations=medium_recommendations,
            conclusion="Для получения полного отчёта с пошаговыми инструкциями по устранению свяжитесь с нами.",
            status="draft",
        )
        db.add(medium_report)
        
        # === 3. ДЕМО ОТЧЁТ (только статистика и риски, без деталей) ===
        demo_findings = f"""Обнаружено {len(vulns)} уязвимостей:
• Критических: {severity_counts['critical']}
• Высоких: {severity_counts['high']}
• Средних: {severity_counts['medium']}
• Низких: {severity_counts['low']}

Примеры обнаруженных проблем:
- {vuln_details[0]['type']} ({vuln_details[0]['severity'].upper()})"""
        
        if len(vuln_details) > 1:
            demo_findings += f"\n- {vuln_details[1]['type']} ({vuln_details[1]['severity'].upper()})"
        
        demo_findings += "\n\n... и ещё " + str(max(0, len(vulns) - 2)) + " уязвимостей"
        demo_findings += "\n\n⚠️ Детальная информация о каждой уязвимости, шаги воспроизведения и доказательства доступны в полной версии отчёта."
        
        demo_report = ScanReport(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            report_type="demo",
            title=f"[Демо] {target_url}",
            target_url=target_url,
            category=category,
            executive_summary=ai_data.get("executive_summary", ""),
            findings_summary=demo_findings,
            risk_assessment=ai_data.get("risk_assessment", ""),
            compliance_notes="Выявлены потенциальные нарушения требований законодательства РФ. Детальный анализ доступен в полной версии.",
            recommendations="Полный перечень рекомендаций с конкретными командами и конфигурациями доступен после оформления услуги.",
            conclusion="Обнаружены серьёзные уязвимости, требующие немедленного внимания. Свяжитесь с нами для получения полного отчёта и плана устранения.",
            status="draft",
        )
        db.add(demo_report)
        
        db.commit()
        logger.info("3 reports (full/medium/demo) created for scan %s", scan_id)
        
    except Exception as e:
        logger.error("AI report generation failed: %s", e)
        _create_basic_reports(scan_id, target_url, category, vulns, vuln_text_full, severity_counts, db)


def _create_basic_reports(scan_id, target_url, category, vulns, vuln_text, severity_counts, db):
    """Создаёт 3 базовых отчёта без AI."""
    from app.models.database import ScanReport
    
    # Full
    db.add(ScanReport(
        id=str(uuid.uuid4()), scan_id=scan_id, report_type="full",
        title=f"[Полный] {target_url}", target_url=target_url, category=category,
        executive_summary=f"Обнаружено {len(vulns)} уязвимостей.",
        findings_summary=vuln_text, risk_assessment="Требуется анализ.",
        recommendations="Требуется анализ.", status="draft",
    ))
    # Medium
    db.add(ScanReport(
        id=str(uuid.uuid4()), scan_id=scan_id, report_type="medium",
        title=f"[Технический] {target_url}", target_url=target_url, category=category,
        executive_summary=f"Обнаружено {len(vulns)} уязвимостей.",
        findings_summary=vuln_text, risk_assessment="Требуется анализ.",
        recommendations="Детальные инструкции доступны в полной версии.", status="draft",
    ))
    # Demo
    demo_text = f"Обнаружено {len(vulns)} уязвимостей: критических {severity_counts['critical']}, высоких {severity_counts['high']}, средних {severity_counts['medium']}."
    db.add(ScanReport(
        id=str(uuid.uuid4()), scan_id=scan_id, report_type="demo",
        title=f"[Демо] {target_url}", target_url=target_url, category=category,
        executive_summary=demo_text, findings_summary="Детали доступны в полной версии.",
        risk_assessment="Требуется анализ.", recommendations="Доступно после оформления услуги.", status="draft",
    ))
    db.commit()


@router.post("/api/scans/batch", status_code=201)
def batch_scan(
    body: BatchScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Пакетное сканирование списка сайтов.
    
    Создаёт сканы в очереди и запускает их последовательно (один за другим).
    """
    import threading
    
    if not body.targets:
        raise HTTPException(status_code=400, detail="Список сайтов пуст")
    
    if len(body.targets) > 300:
        raise HTTPException(status_code=400, detail="Максимум 300 сайтов за раз")
    
    # Подготавливаем список валидных целей
    valid_targets = []
    errors = []
    
    for target_url in body.targets:
        target_url = target_url.strip()
        if not target_url:
            continue
            
        # Добавляем https:// если нет схемы
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = 'https://' + target_url
        
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                errors.append({"url": target_url, "error": "Некорректный URL"})
                continue
            valid_targets.append({"url": target_url, "domain": parsed.netloc})
        except Exception:
            errors.append({"url": target_url, "error": "Некорректный URL"})
            continue
    
    # Создаём все программы и активы
    scan_queue = []
    
    for target in valid_targets:
        program_id = str(uuid.uuid4())
        program = Program(
            id=program_id,
            name=f"Batch Scan: {target['domain']}",
            platform="batch_scan",
            raw_text=f"Batch scan target: {target['url']}, category: {body.category}",
            is_archived=False,
        )
        db.add(program)
        
        asset_id = str(uuid.uuid4())
        asset_db = AssetDB(
            id=asset_id,
            program_id=program_id,
            name=target['domain'],
            asset_type="web_application",
            target=target['url'],
            in_scope=True,
            notes=f"Batch scan, category: {body.category}",
        )
        db.add(asset_db)
        
        scan_queue.append({
            "program_id": program_id,
            "asset_id": asset_id,
            "target_url": target['url'],
            "domain": target['domain'],
        })
    
    db.commit()
    
    # Запускаем фоновый воркер для последовательного выполнения
    def run_queue(queue, category, auto_ai):
        """Последовательно запускает сканы из очереди."""
        from app.core.database import SessionLocal
        
        for item in queue:
            local_db = SessionLocal()
            try:
                # Создаём Asset schema
                asset = Asset(
                    id=item['asset_id'],
                    name=item['domain'],
                    asset_type=AssetType("web_application"),
                    target=item['target_url'],
                    in_scope=True,
                    notes=f"Batch scan, category: {category}",
                )
                
                scan_config = ScanConfig(
                    asset_id=item['asset_id'],
                    program_id=item['program_id'],
                    check_types=[],
                )
                
                compliance_manager = ComplianceManager()
                rules = compliance_manager.load_program_rules(item['program_id'], local_db)
                
                # Запускаем скан (start_scan сам создаёт запись в БД)
                progress = _scanner.start_scan(asset, scan_config, compliance_manager, rules, local_db)
                
                # Обновляем категорию
                scan_rec = local_db.query(Scan).filter(Scan.id == progress.scan_id).first()
                if scan_rec:
                    scan_rec.category = category
                    local_db.commit()
                
                # После Stage 1 — запускаем AI Stage 2 + генерируем отчёты
                if auto_ai and progress.status.value == "completed":
                    try:
                        _run_stage2_and_reports(progress.scan_id, item, category, local_db)
                    except Exception as e:
                        logger.error("AI Stage 2 failed for scan %s: %s", progress.scan_id, e)
                        # Всё равно генерируем отчёты на основе Stage 1
                        try:
                            _run_ai_and_create_report(progress.scan_id, category, local_db)
                        except Exception as e2:
                            logger.error("Report generation also failed: %s", e2)
                
            except Exception as e:
                logger.error("Batch scan failed for %s: %s", item['target_url'], e)
            finally:
                local_db.close()
    
    # Запускаем в фоновом потоке
    thread = threading.Thread(
        target=run_queue,
        args=(scan_queue, body.category, body.auto_ai_analysis),
        daemon=True,
    )
    thread.start()
    
    results = [{"target_url": s["target_url"], "status": "queued"} for s in scan_queue]
    
    return {
        "total": len(results) + len(errors),
        "started": len(results),
        "failed": len(errors),
        "scans": results,
        "errors": errors,
        "category": body.category,
    }


@router.get("/api/scans")
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """Список всех сканирований."""
    scans = db.query(Scan).order_by(Scan.started_at.desc()).offset(offset).limit(limit).all()
    
    result = []
    for scan in scans:
        scan_dict = _scan_to_response(scan)
        # Добавляем target_url из актива
        if scan.asset_id:
            asset = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
            if asset:
                scan_dict["target_url"] = asset.target
                scan_dict["target_name"] = asset.name
        result.append(scan_dict)
    
    return result


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


@router.post("/api/scans/{scan_id}/stop")
def stop_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Остановить сканирование (Stage 1).
    
    Немедленно останавливает текущее сканирование.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    if scan.status not in ("running", "pending"):
        raise HTTPException(status_code=400, detail=f"Сканирование не запущено (статус: {scan.status})")
    
    # Останавливаем сканирование
    stopped = _scanner.stop_scan(scan_id, db)
    
    if stopped:
        return {
            "status": "stopped",
            "message": "Сканирование остановлено",
            "scan_id": scan_id,
        }
    else:
        raise HTTPException(status_code=500, detail="Не удалось остановить сканирование")


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


class AIAnalyzeRequest(BaseModel):
    """Настройки ИИ-анализа."""
    supervised_mode: bool = False
    max_iterations: int = 3
    max_requests: int = 50
    rate_limit: float = 5.0


@router.post("/api/scans/{scan_id}/ai-analyze")
def start_ai_analysis(
    scan_id: str,
    body: AIAnalyzeRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Запуск ИИ-анализа (Stage 2) для завершённого сканирования.
    
    Анализирует найденные уязвимости и генерирует дополнительные гипотезы.
    Требует настроенный API-ключ LLM провайдера.
    """
    import os
    import threading
    from app.models.database import VulnerabilityRecord, AIScanState
    from app.models.schemas import RawFinding
    from app.services.ai.ai_scanner import AIScanner
    from app.services.ai.llm_provider_manager import LLMProviderManager
    from app.models.ai_schemas import LLMConfig, ProviderType
    
    if body is None:
        body = AIAnalyzeRequest()
    
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Сканирование должно быть завершено для ИИ-анализа")
    
    # Проверяем, не запущен ли уже AI-анализ
    existing_state = db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
    if existing_state and existing_state.status == "running":
        raise HTTPException(status_code=400, detail="ИИ-анализ уже запущен для этого сканирования")
    
    # Получаем актив
    asset_row = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
    if asset_row is None:
        raise HTTPException(status_code=404, detail="Актив не найден")
    
    # Проверяем наличие уязвимостей
    vulns = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id == scan_id).all()
    
    if not vulns:
        raise HTTPException(status_code=400, detail="Нет уязвимостей для анализа")
    
    # Проверяем API ключ (приоритет: Anthropic > DeepSeek)
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    deepseek_key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("LLM_API_KEY")
    
    # Также проверяем сохранённую конфигурацию в БД
    llm_manager = LLMProviderManager(db_session=db)
    saved_config = llm_manager.load_provider_config()
    
    if not anthropic_key and not deepseek_key and (not saved_config or not saved_config.api_key):
        raise HTTPException(
            status_code=400, 
            detail="API-ключ LLM не настроен. Установите ANTHROPIC_API_KEY или DEEPSEEK_API_KEY"
        )
    
    # Создаём конфигурацию LLM (приоритет: сохранённая > Anthropic > DeepSeek)
    if saved_config and saved_config.api_key:
        llm_config = saved_config
    elif anthropic_key:
        # Используем Claude Opus 4.6 по умолчанию
        llm_config = LLMConfig(
            provider=ProviderType.ANTHROPIC,
            api_key=anthropic_key,
            base_url="https://api.anthropic.com",
            model="claude-opus-4-6",
            temperature=0.3,
            max_tokens=8192,
        )
    else:
        llm_config = LLMConfig(
            provider=ProviderType.DEEPSEEK,
            api_key=deepseek_key,
            base_url="https://api.deepseek.com",
            model="deepseek-v4-pro",
            temperature=0.3,
        )
    
    # Конвертируем уязвимости в RawFinding
    stage1_results = []
    for v in vulns:
        # Загружаем raw_data из JSON
        raw_data = {}
        if hasattr(v, 'raw_data_json') and v.raw_data_json:
            try:
                raw_data = json.loads(v.raw_data_json)
            except json.JSONDecodeError:
                pass
        
        # Добавляем базовые данные
        raw_data.update({
            "severity": v.severity,
            "steps": v.steps_to_reproduce,
            "impact": v.impact_assessment,
            "source": "stage1_scan",
        })
        
        stage1_results.append(RawFinding(
            vulnerability_type=v.vulnerability_type,
            description=v.description or "Уязвимость обнаружена сканером",
            evidence=v.evidence or "",
            affected_asset_id=scan.asset_id,
            raw_data=raw_data,
        ))
    
    # Запускаем AI-анализ в фоновом потоке
    def run_ai_analysis():
        from app.core.database import SessionLocal
        thread_db = SessionLocal()
        try:
            thread_llm_manager = LLMProviderManager(db_session=thread_db)
            
            # Если есть сохранённая конфигурация, используем её
            if saved_config and saved_config.api_key:
                # Конфигурация уже загружена
                pass
            else:
                # Сохраняем конфигурацию с API ключом
                thread_llm_manager.save_provider_config(llm_config)
            
            ai_scanner = AIScanner(
                llm_manager=thread_llm_manager,
                db=thread_db,
            )
            
            result = ai_scanner.run_stage2(
                scan_id=scan_id,
                stage1_results=stage1_results,
                target_url=asset_row.target,
                program_id=scan.program_id,
                supervised_mode=body.supervised_mode,
                max_iterations=body.max_iterations,
                max_requests=body.max_requests,
                rate_limit=body.rate_limit,
            )
            
            # Логируем результат
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"AI Analysis completed for scan {scan_id}: {result.status}, {len(result.findings)} findings")
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(f"AI Analysis failed for scan {scan_id}: {e}")
            
            # Обновляем статус на failed
            state = thread_db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
            if state:
                state.status = "failed"
                state.current_phase = "failed"
                thread_db.commit()
        finally:
            thread_db.close()
    
    # Запускаем в отдельном потоке
    thread = threading.Thread(target=run_ai_analysis, daemon=True)
    thread.start()
    
    return {
        "status": "started",
        "message": f"ИИ-анализ запущен для {len(vulns)} уязвимостей. Отслеживайте прогресс через /api/scans/{scan_id}/ai-status",
        "scan_id": scan_id,
        "vulnerabilities_count": len(vulns),
        "settings": {
            "supervised_mode": body.supervised_mode,
            "max_iterations": body.max_iterations,
            "max_requests": body.max_requests,
            "rate_limit": body.rate_limit,
        }
    }


@router.get("/api/scans/{scan_id}/ai-status")
def get_ai_analysis_status(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Получить статус ИИ-анализа (Stage 2).
    
    Возвращает текущую фазу, прогресс и найденные уязвимости.
    """
    from app.models.database import AIScanState, AIFindingRecord
    
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    state = db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
    if state is None:
        return {
            "status": "not_started",
            "message": "ИИ-анализ не запускался для этого сканирования",
            "scan_id": scan_id,
        }
    
    # Получаем AI findings
    ai_findings = db.query(AIFindingRecord).filter(AIFindingRecord.scan_id == scan_id).all()
    
    # Вычисляем прогресс
    total_hypotheses = state.hypotheses_generated or 0
    tested = state.hypotheses_tested or 0
    percent = int((tested / total_hypotheses * 100) if total_hypotheses > 0 else 0)
    
    return {
        "status": state.status,
        "current_phase": state.current_phase,
        "percent_complete": min(percent, 100),
        "scan_id": scan_id,
        "stats": {
            "technologies_found": state.technologies_found or 0,
            "hypotheses_generated": state.hypotheses_generated or 0,
            "hypotheses_tested": state.hypotheses_tested or 0,
            "requests_executed": state.requests_executed or 0,
            "requests_blocked": state.requests_blocked or 0,
            "findings_confirmed": state.findings_confirmed or 0,
        },
        "settings": {
            "supervised_mode": state.supervised_mode,
            "max_iterations": state.max_iterations,
            "max_requests": state.max_requests,
            "rate_limit": state.rate_limit,
        },
        "ai_findings": [
            {
                "id": f.id,
                "vulnerability_type": f.vulnerability_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "description": f.description,
                "requires_manual_review": f.requires_manual_review,
            }
            for f in ai_findings
        ],
        "started_at": state.started_at.isoformat() if state.started_at else None,
        "completed_at": state.completed_at.isoformat() if state.completed_at else None,
    }


@router.post("/api/scans/{scan_id}/ai-stop")
def stop_ai_analysis(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Остановить ИИ-анализ (Kill Switch).
    
    Немедленно останавливает текущий AI-анализ.
    """
    from app.models.database import AIScanState
    
    state = db.query(AIScanState).filter(AIScanState.scan_id == scan_id).first()
    if state is None:
        raise HTTPException(status_code=404, detail="ИИ-анализ не найден")
    
    if state.status != "running":
        raise HTTPException(status_code=400, detail=f"ИИ-анализ не запущен (статус: {state.status})")
    
    # Обновляем статус на cancelled
    state.status = "cancelled"
    state.current_phase = "cancelled"
    from datetime import datetime, UTC
    state.completed_at = datetime.now(UTC)
    db.commit()
    
    return {
        "status": "cancelled",
        "message": "ИИ-анализ остановлен",
        "scan_id": scan_id,
    }


class ProfessionalReportRequest(BaseModel):
    """Запрос на генерацию профессионального отчёта."""
    company_name: str = "Клиент"
    industry: str = "general"  # fintech, ecommerce, healthcare, government, general
    include_executive_summary: bool = True
    use_ai_descriptions: bool = True


@router.post("/api/scans/{scan_id}/professional-report")
def generate_professional_report(
    scan_id: str,
    body: ProfessionalReportRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Генерирует профессиональный PDF-отчёт с графиками.
    
    Использует DeepSeek для генерации Executive Summary и рекомендаций.
    Возвращает PDF-файл.
    """
    from fastapi.responses import Response
    from app.services.professional_report import ProfessionalReportGenerator
    
    if body is None:
        body = ProfessionalReportRequest()
    
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Сканирование должно быть завершено для генерации отчёта")
    
    try:
        generator = ProfessionalReportGenerator(db)
        pdf_bytes = generator.generate_report(
            scan_id=scan_id,
            company_name=body.company_name,
            industry=body.industry,
            include_executive_summary=body.include_executive_summary,
            use_ai_descriptions=body.use_ai_descriptions,
        )
        
        # Формируем имя файла
        asset = db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
        target_name = asset.name if asset else "scan"
        filename = f"security_report_{target_name}_{scan_id[:8]}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.exception("Failed to generate professional report: %s", e)
        raise HTTPException(status_code=500, detail=f"Ошибка генерации отчёта: {str(e)}")

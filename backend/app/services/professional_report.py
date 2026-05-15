"""Профессиональный генератор PDF-отчётов с графиками.

Создаёт красивые PDF-отчёты для клиентов с:
- Executive Summary
- Графиками распределения уязвимостей
- Детальным описанием каждой уязвимости
- Оценкой бизнес-рисков
- Рекомендациями по устранению

Использует DeepSeek V4 Pro для генерации текстов.
"""

from __future__ import annotations

import io
import json
import logging
import os
from datetime import datetime, UTC
from typing import Any

# Matplotlib setup - must be before import
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server
import matplotlib.pyplot as plt
from matplotlib import font_manager

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from sqlalchemy.orm import Session

from app.models.database import VulnerabilityRecord, Scan
from app.models.database import Asset as AssetDB

logger = logging.getLogger(__name__)

# Регистрируем шрифт с поддержкой кириллицы
_FONT_REGISTERED = False

def _register_cyrillic_font():
    """Регистрирует шрифт DejaVu с поддержкой кириллицы."""
    global _FONT_REGISTERED
    if _FONT_REGISTERED:
        return
    
    # Пути к шрифтам DejaVu (обычно есть в Linux)
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "C:/Windows/Fonts/arial.ttf",  # Windows fallback
    ]
    
    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont('DejaVu', font_path))
                logger.info("Registered Cyrillic font: %s", font_path)
                _FONT_REGISTERED = True
                return
            except Exception as e:
                logger.warning("Failed to register font %s: %s", font_path, e)
    
    logger.warning("No Cyrillic font found, using Helvetica (no Cyrillic support)")
    _FONT_REGISTERED = True


# Цвета для severity
SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "informational": "#6B7280",
}

SEVERITY_LABELS_RU = {
    "critical": "Критические",
    "high": "Высокие",
    "medium": "Средние",
    "low": "Низкие",
    "informational": "Информационные",
}

# Бизнес-метрики для оценки потерь (в рублях)
BUSINESS_IMPACT = {
    "critical": {
        "min_loss": 50000000,
        "max_loss": 500000000,
        "avg_loss": 150000000,
        "recovery_days": 30,
        "reputation_impact": "Катастрофический",
        "examples": [
            "Полная компрометация базы данных клиентов",
            "Утечка платёжных данных (нарушение PCI DSS)",
            "Удалённое выполнение кода на сервере",
            "Полный захват инфраструктуры",
        ],
    },
    "high": {
        "min_loss": 10000000,
        "max_loss": 50000000,
        "avg_loss": 25000000,
        "recovery_days": 14,
        "reputation_impact": "Серьёзный",
        "examples": [
            "Несанкционированный доступ к аккаунтам",
            "Утечка персональных данных (штраф по 152-ФЗ)",
            "SQL-инъекция с доступом к данным",
            "Обход аутентификации",
        ],
    },
    "medium": {
        "min_loss": 1000000,
        "max_loss": 10000000,
        "avg_loss": 5000000,
        "recovery_days": 7,
        "reputation_impact": "Умеренный",
        "examples": [
            "XSS атаки на пользователей",
            "Раскрытие внутренней информации",
            "CSRF атаки",
            "Небезопасная конфигурация",
        ],
    },
    "low": {
        "min_loss": 100000,
        "max_loss": 1000000,
        "avg_loss": 500000,
        "recovery_days": 3,
        "reputation_impact": "Минимальный",
        "examples": [
            "Раскрытие версий ПО",
            "Отсутствие security headers",
            "Информационные утечки",
        ],
    },
    "informational": {
        "min_loss": 0,
        "max_loss": 100000,
        "avg_loss": 50000,
        "recovery_days": 1,
        "reputation_impact": "Отсутствует",
        "examples": [
            "Рекомендации по улучшению",
            "Best practices",
        ],
    },
}

# Отрасли и их специфика
INDUSTRY_INFO = {
    "fintech": {
        "name": "Финтех / Банки",
        "regulations": ["152-ФЗ", "PCI DSS", "ГОСТ Р 57580", "683-П ЦБ РФ"],
        "risks": "Финансовые потери клиентов, отзыв лицензии ЦБ, уголовная ответственность",
        "data_types": "Платёжные данные, банковская тайна, персональные данные",
    },
    "ecommerce": {
        "name": "E-commerce / Ритейл",
        "regulations": ["152-ФЗ", "PCI DSS", "Закон о защите прав потребителей"],
        "risks": "Утечка данных покупателей, мошенничество с картами, потеря репутации",
        "data_types": "Данные карт, адреса доставки, история покупок",
    },
    "healthcare": {
        "name": "Медицина / Здравоохранение",
        "regulations": ["152-ФЗ", "323-ФЗ", "Врачебная тайна"],
        "risks": "Утечка медицинских данных, угроза жизни пациентов, уголовная ответственность",
        "data_types": "Медицинские карты, диагнозы, результаты анализов",
    },
    "government": {
        "name": "Госсектор / КИИ",
        "regulations": ["187-ФЗ", "152-ФЗ", "Приказы ФСТЭК", "ФСБ требования"],
        "risks": "Угроза национальной безопасности, уголовная ответственность до 10 лет",
        "data_types": "Государственная тайна, персональные данные граждан",
    },
    "general": {
        "name": "Общий бизнес",
        "regulations": ["152-ФЗ", "Приказ ФСТЭК №21"],
        "risks": "Утечка данных, репутационный ущерб, штрафы регуляторов",
        "data_types": "Персональные данные, коммерческая тайна",
    },
}


class ProfessionalReportGenerator:
    """Генератор профессиональных PDF-отчётов."""

    def __init__(self, db: Session):
        self.db = db
        _register_cyrillic_font()
        self._font_name = 'DejaVu' if _FONT_REGISTERED else 'Helvetica'
        self._styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Настройка стилей для PDF с кириллицей."""
        font = self._font_name
        
        if 'ReportTitle' not in self._styles.byName:
            self._styles.add(ParagraphStyle(
                name='ReportTitle',
                fontSize=24,
                leading=30,
                alignment=TA_CENTER,
                spaceAfter=20,
                textColor=colors.HexColor("#1E293B"),
                fontName=font,
            ))
        
        if 'SectionTitle' not in self._styles.byName:
            self._styles.add(ParagraphStyle(
                name='SectionTitle',
                fontSize=16,
                leading=20,
                spaceBefore=20,
                spaceAfter=10,
                textColor=colors.HexColor("#1E40AF"),
                fontName=font,
            ))
        
        if 'CustomBody' not in self._styles.byName:
            self._styles.add(ParagraphStyle(
                name='CustomBody',
                fontSize=10,
                leading=14,
                alignment=TA_JUSTIFY,
                spaceAfter=8,
                textColor=colors.HexColor("#374151"),
                fontName=font,
            ))
        
        if 'VulnTitle' not in self._styles.byName:
            self._styles.add(ParagraphStyle(
                name='VulnTitle',
                fontSize=12,
                leading=16,
                spaceBefore=15,
                spaceAfter=5,
                textColor=colors.HexColor("#1E293B"),
                fontName=font,
            ))

    def generate_report(
        self,
        scan_id: str,
        company_name: str = "Клиент",
        industry: str = "general",
        include_executive_summary: bool = True,
        use_ai_descriptions: bool = True,
    ) -> bytes:
        """Генерирует профессиональный PDF-отчёт."""
        logger.info("Generating professional report for scan %s, industry=%s", scan_id, industry)
        
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        asset = self.db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
        target_url = asset.target if asset else "Unknown"
        
        vulns = self.db.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan_id
        ).all()
        
        stats = self._calculate_stats(vulns)
        
        # Full AI Analysis - single comprehensive request
        ai_analysis = None
        if use_ai_descriptions:
            ai_analysis = self._generate_full_ai_analysis(vulns, target_url, company_name, industry, stats)
        
        # Create PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
        )
        
        story = []
        
        # Title page
        story.extend(self._create_title_page(company_name, target_url, scan, stats, industry))
        story.append(PageBreak())
        
        # Executive Summary (AI-generated)
        if include_executive_summary:
            story.extend(self._create_executive_summary_ai(stats, ai_analysis, company_name, industry))
            story.append(PageBreak())
        
        # Business Impact & Metrics (AI-enhanced)
        story.extend(self._create_business_impact_section_ai(stats, vulns, ai_analysis, industry))
        story.append(PageBreak())
        
        # Charts with AI trend analysis
        story.extend(self._create_charts_section_ai(stats, ai_analysis))
        story.append(PageBreak())
        
        # Vulnerabilities with AI descriptions
        story.extend(self._create_vulnerabilities_section_ai(vulns, ai_analysis))
        
        # Recommendations (AI-generated specific steps)
        story.append(PageBreak())
        story.extend(self._create_recommendations_section_ai(vulns, ai_analysis))
        
        doc.build(story)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        logger.info("Report generated: %d bytes", len(pdf_bytes))
        return pdf_bytes

    def _calculate_stats(self, vulns: list[VulnerabilityRecord]) -> dict:
        """Подсчёт статистики."""
        stats = {
            "total": len(vulns),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "by_type": {},
        }
        
        for v in vulns:
            severity = v.severity.lower() if v.severity else "informational"
            if severity in stats:
                stats[severity] += 1
            
            vuln_type = v.vulnerability_type or "unknown"
            if vuln_type not in stats["by_type"]:
                stats["by_type"][vuln_type] = 0
            stats["by_type"][vuln_type] += 1
        
        return stats

    def _generate_full_ai_analysis(
        self,
        vulns: list[VulnerabilityRecord],
        target_url: str,
        company_name: str,
        industry: str,
        stats: dict,
    ) -> dict | None:
        """Генерирует полный AI-анализ через DeepSeek."""
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            logger.warning("DEEPSEEK_API_KEY not set, skipping AI analysis")
            return None
        
        industry_info = INDUSTRY_INFO.get(industry, INDUSTRY_INFO["general"])
        
        try:
            import httpx
            
            # Prepare vulnerability summary
            vuln_summary = []
            for v in vulns[:25]:
                vuln_summary.append({
                    "type": v.vulnerability_type,
                    "severity": v.severity,
                    "description": (v.description or "")[:300],
                })
            
            prompt = f"""Ты — ведущий эксперт по кибербезопасности с 15-летним опытом. Создай ПОЛНЫЙ профессиональный анализ безопасности.

КОНТЕКСТ:
- Цель сканирования: {target_url}
- Компания: {company_name}
- Отрасль: {industry_info['name']}
- Применимые регуляции: {', '.join(industry_info['regulations'])}
- Типы данных под угрозой: {industry_info['data_types']}

СТАТИСТИКА:
- Всего уязвимостей: {stats['total']}
- Критических: {stats['critical']}
- Высоких: {stats['high']}
- Средних: {stats['medium']}
- Низких: {stats['low']}

НАЙДЕННЫЕ УЯЗВИМОСТИ:
{json.dumps(vuln_summary, ensure_ascii=False, indent=2)}

Сгенерируй JSON со следующими полями (ВСЕ НА РУССКОМ ЯЗЫКЕ):

{{
  "executive_summary": "Резюме для руководства: 3-4 абзаца с общей оценкой, ключевыми рисками для бизнеса в отрасли {industry_info['name']}, и срочностью действий",
  
  "overall_score": число от 1 до 10 (10 = отлично защищён),
  
  "risk_level": "КРИТИЧЕСКИЙ/ВЫСОКИЙ/СРЕДНИЙ/НИЗКИЙ",
  
  "industry_specific_risks": "2-3 абзаца о специфических рисках для отрасли {industry_info['name']} на основе найденных уязвимостей",
  
  "chart_analysis": "Анализ распределения уязвимостей: что показывают графики, какие тренды видны, на что обратить внимание",
  
  "attack_scenarios": [
    {{
      "name": "Название сценария атаки",
      "description": "Как злоумышленник может использовать найденные уязвимости",
      "impact": "Последствия для бизнеса",
      "probability": "ВЫСОКАЯ/СРЕДНЯЯ/НИЗКАЯ"
    }}
  ],
  
  "compliance_violations": [
    {{
      "regulation": "Название закона/стандарта",
      "violation": "Какое требование нарушено",
      "penalty": "Возможные санкции",
      "based_on": "На основе каких уязвимостей"
    }}
  ],
  
  "remediation_steps": [
    {{
      "priority": 1,
      "title": "Название действия",
      "description": "Подробное описание что нужно сделать",
      "commands": ["конкретная команда 1", "команда 2"],
      "timeline": "Срок выполнения",
      "responsible": "Кто должен выполнить"
    }}
  ],
  
  "vulnerabilities_analysis": [
    {{
      "type": "тип уязвимости",
      "title_ru": "Название на русском",
      "description_ru": "Описание на русском",
      "business_impact": "Влияние на бизнес",
      "remediation_ru": "Рекомендации по устранению на русском с конкретными шагами"
    }}
  ]
}}

ВАЖНО:
- Все тексты на русском языке
- Анализ должен быть основан ТОЛЬКО на реально найденных уязвимостях
- Не придумывай уязвимости которых нет
- Рекомендации должны быть конкретными с командами и шагами
- Учитывай специфику отрасли {industry_info['name']}

Отвечай ТОЛЬКО валидным JSON без markdown."""

            response = httpx.post(
                "https://api.deepseek.com/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "deepseek-chat",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 6000,
                },
                timeout=120.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                # Clean markdown if present
                content = content.strip()
                if content.startswith("```"):
                    content = content.split("\n", 1)[1]
                if content.endswith("```"):
                    content = content.rsplit("```", 1)[0]
                content = content.strip()
                
                result = json.loads(content)
                logger.info("AI analysis generated successfully")
                return result
            else:
                logger.error("DeepSeek API error: %s", response.text)
                return None
                
        except Exception as e:
            logger.exception("Failed to generate AI analysis: %s", e)
            return None

    def _create_title_page(
        self,
        company_name: str,
        target_url: str,
        scan: Scan,
        stats: dict,
        industry: str = "general",
    ) -> list:
        """Создаёт титульную страницу."""
        story = []
        
        industry_info = INDUSTRY_INFO.get(industry, INDUSTRY_INFO["general"])
        
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph(
            "ОТЧЁТ О ТЕСТИРОВАНИИ<br/>БЕЗОПАСНОСТИ",
            self._styles['ReportTitle']
        ))
        
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(
            f"<i>{industry_info['name']}</i>",
            ParagraphStyle(
                'IndustryLabel',
                fontSize=12,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#6B7280"),
                fontName=self._font_name,
            )
        ))
        
        story.append(Spacer(1, 1*cm))
        
        story.append(Paragraph(
            f"<b>Клиент:</b> {company_name}",
            self._styles['CustomBody']
        ))
        story.append(Paragraph(
            f"<b>Цель тестирования:</b> {target_url}",
            self._styles['CustomBody']
        ))
        story.append(Paragraph(
            f"<b>Дата сканирования:</b> {scan.started_at.strftime('%d.%m.%Y %H:%M') if scan.started_at else 'N/A'}",
            self._styles['CustomBody']
        ))
        
        story.append(Spacer(1, 2*cm))
        
        # Summary table
        summary_data = [
            ["Показатель", "Значение"],
            ["Всего уязвимостей", str(stats["total"])],
            ["Критических", str(stats["critical"])],
            ["Высоких", str(stats["high"])],
            ["Средних", str(stats["medium"])],
            ["Низких", str(stats["low"])],
        ]
        
        summary_table = Table(summary_data, colWidths=[8*cm, 4*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E40AF")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), self._font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F1F5F9")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ]))
        
        story.append(summary_table)
        
        story.append(Spacer(1, 3*cm))
        
        story.append(Paragraph(
            "<b>КОНФИДЕНЦИАЛЬНО</b><br/>"
            "Данный отчёт содержит конфиденциальную информацию и предназначен "
            "исключительно для внутреннего использования.",
            ParagraphStyle(
                'Confidential',
                fontSize=9,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#DC2626"),
                fontName=self._font_name,
            )
        ))
        
        return story

    def _create_executive_summary(
        self,
        stats: dict,
        ai_summary: dict | None,
        company_name: str,
    ) -> list:
        """Создаёт Executive Summary."""
        story = []
        
        story.append(Paragraph("РЕЗЮМЕ ДЛЯ РУКОВОДСТВА", self._styles['SectionTitle']))
        
        if ai_summary and "executive_summary" in ai_summary:
            clean_summary = self._clean_text(ai_summary["executive_summary"])
            story.append(Paragraph(clean_summary, self._styles['CustomBody']))
        else:
            critical_high = stats["critical"] + stats["high"]
            risk_level = "ВЫСОКИЙ" if critical_high > 0 else "СРЕДНИЙ" if stats["medium"] > 0 else "НИЗКИЙ"
            
            summary_text = f"""
            В ходе тестирования безопасности было обнаружено <b>{stats['total']}</b> уязвимостей, 
            из которых <b>{stats['critical']}</b> критических и <b>{stats['high']}</b> высокой степени серьёзности.
            <br/><br/>
            Общий уровень риска оценивается как <b>{risk_level}</b>.
            <br/><br/>
            Рекомендуется незамедлительно устранить критические и высокие уязвимости для 
            предотвращения потенциальных инцидентов безопасности.
            """
            story.append(Paragraph(summary_text, self._styles['CustomBody']))
        
        # Risk assessment
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("Оценка бизнес-рисков", self._styles['VulnTitle']))
        
        if ai_summary and "risk_assessment" in ai_summary:
            clean_risk = self._clean_text(ai_summary["risk_assessment"])
            story.append(Paragraph(clean_risk, self._styles['CustomBody']))
        else:
            risk_text = """
            Обнаруженные уязвимости могут привести к:<br/>
            • Несанкционированному доступу к конфиденциальным данным<br/>
            • Компрометации учётных записей пользователей<br/>
            • Финансовым потерям и репутационному ущербу<br/>
            • Нарушению требований регуляторов (GDPR, 152-ФЗ)
            """
            story.append(Paragraph(risk_text, self._styles['CustomBody']))
        
        # Score
        if ai_summary and "overall_score" in ai_summary:
            score = ai_summary["overall_score"]
            story.append(Spacer(1, 0.5*cm))
            story.append(Paragraph(
                f"<b>Оценка безопасности: {score}/10</b>",
                self._styles['VulnTitle']
            ))
        
        return story

    def _create_business_impact_section(self, stats: dict, vulns: list[VulnerabilityRecord]) -> list:
        """Создаёт секцию с бизнес-метриками и оценкой потерь на основе найденных уязвимостей."""
        story = []
        
        story.append(Paragraph("ОЦЕНКА БИЗНЕС-ВЛИЯНИЯ", self._styles['SectionTitle']))
        
        # Analyze vulnerability types for compliance mapping
        vuln_types = set()
        vuln_categories = {
            "data_leak": False,      # Утечка данных -> 152-ФЗ
            "auth_bypass": False,    # Обход аутентификации -> все
            "injection": False,      # Инъекции -> все
            "xss": False,            # XSS -> 152-ФЗ, PCI DSS
            "payment": False,        # Платёжные данные -> PCI DSS
            "rce": False,            # RCE -> 187-ФЗ КИИ
            "config": False,         # Конфигурация -> ГОСТ, ФСТЭК
            "crypto": False,         # Криптография -> ГОСТ
        }
        
        for v in vulns:
            vtype = (v.vulnerability_type or "").lower()
            vuln_types.add(vtype)
            desc = (v.description or "").lower()
            
            # Categorize vulnerabilities
            if any(x in vtype for x in ["sql", "injection", "sqli"]):
                vuln_categories["injection"] = True
                vuln_categories["data_leak"] = True
            if any(x in vtype for x in ["xss", "cross-site", "script"]):
                vuln_categories["xss"] = True
            if any(x in vtype for x in ["auth", "login", "session", "bypass", "credential"]):
                vuln_categories["auth_bypass"] = True
            if any(x in vtype for x in ["rce", "remote-code", "command", "exec"]):
                vuln_categories["rce"] = True
            if any(x in vtype for x in ["payment", "card", "credit", "pci"]):
                vuln_categories["payment"] = True
            if any(x in vtype for x in ["config", "misconfiguration", "default", "exposure"]):
                vuln_categories["config"] = True
            if any(x in vtype for x in ["ssl", "tls", "crypto", "certificate", "weak"]):
                vuln_categories["crypto"] = True
            if any(x in vtype for x in ["leak", "disclosure", "sensitive", "personal", "data"]):
                vuln_categories["data_leak"] = True
            
            # Check description too
            if "персональн" in desc or "personal" in desc or "пользовател" in desc:
                vuln_categories["data_leak"] = True
        
        # Calculate potential losses
        total_min_loss = 0
        total_max_loss = 0
        total_avg_loss = 0
        max_recovery_days = 0
        
        for severity in ["critical", "high", "medium", "low", "informational"]:
            count = stats.get(severity, 0)
            if count > 0:
                impact = BUSINESS_IMPACT[severity]
                total_min_loss += impact["min_loss"] * count
                total_max_loss += impact["max_loss"] * count
                total_avg_loss += impact["avg_loss"] * count
                max_recovery_days = max(max_recovery_days, impact["recovery_days"])
        
        # Format currency in rubles
        def fmt_currency(val):
            if val >= 1000000000:
                return f"{val/1000000000:.1f} млрд ₽"
            elif val >= 1000000:
                return f"{val/1000000:.0f} млн ₽"
            elif val >= 1000:
                return f"{val/1000:.0f} тыс ₽"
            else:
                return f"{val:.0f} ₽"
        
        # Key metrics table
        story.append(Paragraph("<b>Ключевые финансовые показатели</b>", self._styles['VulnTitle']))
        story.append(Spacer(1, 0.3*cm))
        
        metrics_data = [
            ["Метрика", "Значение", "Комментарий"],
            ["Минимальные потери", fmt_currency(total_min_loss), "При быстром реагировании"],
            ["Максимальные потери", fmt_currency(total_max_loss), "При отсутствии мер"],
            ["Ожидаемые потери", fmt_currency(total_avg_loss), "Средняя оценка"],
            ["Время восстановления", f"до {max_recovery_days} дней", "После инцидента"],
            ["ROI устранения", f"{(total_avg_loss / max(5000000, 1)):.0f}x", "Окупаемость инвестиций"],
        ]
        
        metrics_table = Table(metrics_data, colWidths=[5*cm, 4*cm, 6*cm])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#DC2626")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), self._font_name),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#FEF2F2")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#FECACA")),
            ('FONTNAME', (1, 1), (1, -1), self._font_name),
            ('TEXTCOLOR', (1, 1), (1, 5), colors.HexColor("#DC2626")),
        ]))
        story.append(metrics_table)
        
        story.append(Spacer(1, 0.8*cm))
        
        # Impact by severity
        story.append(Paragraph("<b>Потенциальные последствия по категориям</b>", self._styles['VulnTitle']))
        story.append(Spacer(1, 0.3*cm))
        
        impact_data = [["Критичность", "Кол-во", "Потери", "Восстановление", "Репутация"]]
        
        for severity in ["critical", "high", "medium", "low"]:
            count = stats.get(severity, 0)
            if count > 0:
                impact = BUSINESS_IMPACT[severity]
                impact_data.append([
                    SEVERITY_LABELS_RU[severity],
                    str(count),
                    f"{fmt_currency(impact['avg_loss'] * count)}",
                    f"{impact['recovery_days']} дн.",
                    impact["reputation_impact"],
                ])
        
        if len(impact_data) > 1:
            impact_table = Table(impact_data, colWidths=[3.5*cm, 2*cm, 3*cm, 3*cm, 3.5*cm])
            
            # Color rows by severity
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E40AF")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), self._font_name),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ]
            
            # Add row colors based on severity
            row_idx = 1
            for severity in ["critical", "high", "medium", "low"]:
                if stats.get(severity, 0) > 0:
                    bg_colors = {
                        "critical": "#FEE2E2",
                        "high": "#FFEDD5",
                        "medium": "#FEF9C3",
                        "low": "#DBEAFE",
                    }
                    table_style.append(('BACKGROUND', (0, row_idx), (-1, row_idx), colors.HexColor(bg_colors[severity])))
                    row_idx += 1
            
            impact_table.setStyle(TableStyle(table_style))
            story.append(impact_table)
        
        story.append(Spacer(1, 0.8*cm))
        
        # Risk scenarios based on ACTUAL vulnerabilities found
        story.append(Paragraph("<b>Сценарии реализации угроз (на основе найденных уязвимостей)</b>", self._styles['VulnTitle']))
        story.append(Spacer(1, 0.2*cm))
        
        scenarios = []
        
        if vuln_categories["rce"] or stats.get("critical", 0) > 0:
            scenarios.append(
                "• <b>Захват системы:</b> Обнаружены уязвимости, позволяющие выполнить произвольный код. "
                "Злоумышленник может получить полный контроль над сервером, похитить данные, установить вредоносное ПО."
            )
        
        if vuln_categories["injection"]:
            scenarios.append(
                "• <b>SQL-инъекция:</b> Найдены уязвимости инъекций. Возможна кража всей базы данных, "
                "модификация или удаление информации, обход аутентификации."
            )
        
        if vuln_categories["data_leak"] or vuln_categories["auth_bypass"]:
            scenarios.append(
                "• <b>Утечка данных:</b> Обнаружены уязвимости, ведущие к раскрытию персональных данных. "
                "Штраф по 152-ФЗ до 18 млн руб., обязательное уведомление Роскомнадзора в течение 24 часов."
            )
        
        if vuln_categories["xss"]:
            scenarios.append(
                "• <b>Атаки на пользователей:</b> Найдены XSS-уязвимости. Возможен перехват сессий, "
                "фишинг от имени сайта, кража учётных данных пользователей."
            )
        
        if vuln_categories["config"] or vuln_categories["crypto"]:
            scenarios.append(
                "• <b>Небезопасная конфигурация:</b> Выявлены проблемы конфигурации и криптографии. "
                "Нарушение требований ГОСТ Р 57580 и Приказа ФСТЭК №21."
            )
        
        if not scenarios:
            scenarios.append(
                "• Критических сценариев атак не выявлено. Найденные уязвимости носят информационный характер. "
                "Рекомендуется устранить для повышения общего уровня защищённости."
            )
        
        for scenario in scenarios:
            story.append(Paragraph(scenario, self._styles['CustomBody']))
        
        story.append(Spacer(1, 0.5*cm))
        
        # Compliance risks - ONLY based on found vulnerabilities
        story.append(Paragraph("<b>Применимые требования законодательства РФ</b>", self._styles['VulnTitle']))
        story.append(Spacer(1, 0.2*cm))
        
        compliance_risks = []
        
        # 152-ФЗ - if data leak or auth issues found
        if vuln_categories["data_leak"] or vuln_categories["auth_bypass"] or vuln_categories["injection"]:
            compliance_risks.append(
                "• <b>152-ФЗ «О персональных данных»</b><br/>"
                "Найденные уязвимости могут привести к утечке ПДн.<br/>"
                "Штраф: до 18 млн руб. Риск блокировки сайта Роскомнадзором."
            )
        
        # 187-ФЗ КИИ - if RCE or critical found
        if vuln_categories["rce"] or stats.get("critical", 0) > 0:
            compliance_risks.append(
                "• <b>187-ФЗ «О безопасности КИИ»</b><br/>"
                "Критические уязвимости создают угрозу для объектов КИИ.<br/>"
                "Риск: уголовная ответственность до 10 лет (ст. 274.1 УК РФ)."
            )
        
        # PCI DSS - if payment or XSS/injection found
        if vuln_categories["payment"] or vuln_categories["xss"] or vuln_categories["injection"]:
            compliance_risks.append(
                "• <b>PCI DSS</b><br/>"
                "Уязвимости угрожают безопасности платёжных данных.<br/>"
                "Штраф: 500 тыс - 10 млн руб./месяц, отзыв права обработки карт."
            )
        
        # ГОСТ Р 57580 - if crypto or config issues
        if vuln_categories["crypto"] or vuln_categories["config"]:
            compliance_risks.append(
                "• <b>ГОСТ Р 57580.1-2017</b><br/>"
                "Нарушены требования к защите информации в финансовых организациях.<br/>"
                "Риск: предписания ЦБ РФ, ограничение операций."
            )
        
        # Приказ ФСТЭК №21 - if any security issues
        if stats.get("critical", 0) > 0 or stats.get("high", 0) > 0 or vuln_categories["config"]:
            compliance_risks.append(
                "• <b>Приказ ФСТЭК России №21</b><br/>"
                "Не выполнены меры по защите ИСПДн.<br/>"
                "Риск: предписания регулятора, внеплановые проверки."
            )
        
        if compliance_risks:
            for risk in compliance_risks:
                story.append(Paragraph(risk, self._styles['CustomBody']))
                story.append(Spacer(1, 0.2*cm))
        else:
            story.append(Paragraph(
                "На основании найденных уязвимостей существенных рисков нарушения законодательства не выявлено. "
                "Рекомендуется поддерживать текущий уровень защищённости.",
                self._styles['CustomBody']
            ))
        
        return story

    def _create_charts_section(self, stats: dict) -> list:
        """Создаёт секцию с графиками."""
        story = []
        
        story.append(Paragraph("ВИЗУАЛИЗАЦИЯ РЕЗУЛЬТАТОВ", self._styles['SectionTitle']))
        
        # Pie chart - square aspect ratio
        pie_chart = self._create_severity_pie_chart(stats)
        if pie_chart:
            story.append(Image(pie_chart, width=12*cm, height=12*cm))
        
        story.append(Spacer(1, 1*cm))
        
        # Bar chart
        if stats["by_type"]:
            bar_chart = self._create_type_bar_chart(stats["by_type"])
            if bar_chart:
                story.append(Image(bar_chart, width=16*cm, height=10*cm))
        
        return story

    def _create_severity_pie_chart(self, stats: dict) -> io.BytesIO | None:
        """Создаёт премиум pie chart с градиентами."""
        try:
            labels = []
            sizes = []
            colors_list = []
            
            for severity in ["critical", "high", "medium", "low", "informational"]:
                if stats[severity] > 0:
                    labels.append(f"{SEVERITY_LABELS_RU[severity]}\n({stats[severity]})")
                    sizes.append(stats[severity])
                    colors_list.append(SEVERITY_COLORS[severity])
            
            if not sizes:
                return None
            
            # Premium style
            plt.style.use('seaborn-v0_8-whitegrid')
            plt.rcParams['font.family'] = ['DejaVu Sans', 'sans-serif']
            plt.rcParams['font.size'] = 11
            
            # Square figure to avoid stretching
            fig, ax = plt.subplots(figsize=(8, 8), facecolor='#0F172A')
            ax.set_facecolor('#0F172A')
            
            # Donut chart with shadow effect
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors_list,
                autopct='%1.1f%%',
                startangle=90,
                explode=[0.03] * len(sizes),
                shadow=True,
                wedgeprops=dict(width=0.6, edgecolor='#1E293B', linewidth=2),
                textprops=dict(color='white', fontweight='bold'),
            )
            
            # Style autotexts
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(12)
            
            for text in texts:
                text.set_color('white')
                text.set_fontsize(11)
            
            # Center circle for donut effect
            centre_circle = plt.Circle((0, 0), 0.35, fc='#0F172A', ec='#334155', linewidth=2)
            ax.add_patch(centre_circle)
            
            # Title
            ax.set_title('Распределение уязвимостей по критичности', 
                        fontsize=14, fontweight='bold', color='white', pad=15)
            
            # Add total in center
            ax.text(0, 0, f'{stats["total"]}\nвсего', ha='center', va='center',
                   fontsize=18, fontweight='bold', color='white')
            
            # Keep aspect ratio equal (circle, not ellipse)
            ax.set_aspect('equal')
            
            plt.tight_layout()
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', 
                       facecolor='#0F172A', edgecolor='none')
            plt.close(fig)
            buf.seek(0)
            
            return buf
            
        except Exception as e:
            logger.exception("Failed to create pie chart: %s", e)
            return None

    def _create_type_bar_chart(self, by_type: dict) -> io.BytesIO | None:
        """Создаёт премиум bar chart с градиентами."""
        try:
            sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]
            
            if not sorted_types:
                return None
            
            # Shorten labels but keep readable
            labels = []
            for t in sorted_types:
                label = t[0].replace('_', ' ').replace('-', ' ')
                if len(label) > 30:
                    label = label[:27] + '...'
                labels.append(label)
            values = [t[1] for t in sorted_types]
            
            # Premium style
            plt.style.use('seaborn-v0_8-whitegrid')
            plt.rcParams['font.family'] = ['DejaVu Sans', 'sans-serif']
            
            fig, ax = plt.subplots(figsize=(14, 8), facecolor='#0F172A')
            ax.set_facecolor('#0F172A')
            
            # Gradient colors from blue to purple
            n = len(values)
            gradient_colors = [plt.cm.cool(i/n) for i in range(n)]
            
            # Horizontal bars
            bars = ax.barh(range(len(labels)), values, color=gradient_colors, 
                          edgecolor='#334155', linewidth=1, height=0.7)
            
            # Add value labels
            for i, (bar, value) in enumerate(zip(bars, values)):
                ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                       str(value), va='center', fontsize=12, fontweight='bold',
                       color='white')
            
            # Style axes - BIGGER FONT for labels
            ax.set_yticks(range(len(labels)))
            ax.set_yticklabels(labels, fontsize=12, color='white', fontweight='bold')
            ax.set_xlabel('Количество', fontsize=14, color='white', fontweight='bold')
            ax.tick_params(axis='x', colors='white', labelsize=11)
            ax.tick_params(axis='y', colors='white')
            
            # Remove spines and add subtle grid
            for spine in ax.spines.values():
                spine.set_color('#334155')
            ax.grid(axis='x', color='#334155', linestyle='--', alpha=0.3)
            
            # Title
            ax.set_title('Топ-10 типов уязвимостей', fontsize=18, fontweight='bold', 
                        color='white', pad=20)
            
            # Add more space on the left for labels
            plt.subplots_adjust(left=0.35)
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                       facecolor='#0F172A', edgecolor='none')
            plt.close(fig)
            buf.seek(0)
            
            return buf
            
        except Exception as e:
            logger.exception("Failed to create bar chart: %s", e)
            return None

    def _create_vulnerabilities_section(self, vulns: list[VulnerabilityRecord]) -> list:
        """Создаёт секцию с уязвимостями."""
        story = []
        
        story.append(Paragraph("ДЕТАЛЬНОЕ ОПИСАНИЕ УЯЗВИМОСТЕЙ", self._styles['SectionTitle']))
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        sorted_vulns = sorted(
            vulns,
            key=lambda v: severity_order.get(v.severity.lower() if v.severity else "informational", 5)
        )
        
        # Translate descriptions in batch for efficiency
        vulns_to_show = sorted_vulns[:30]
        translations = self._translate_vulnerabilities(vulns_to_show)
        
        for i, vuln in enumerate(vulns_to_show, 1):
            severity = vuln.severity.lower() if vuln.severity else "informational"
            severity_color = SEVERITY_COLORS.get(severity, "#6B7280")
            severity_label = SEVERITY_LABELS_RU.get(severity, severity.upper())
            
            # Get translated content or fallback to original
            trans = translations.get(vuln.id, {})
            
            story.append(Paragraph(
                f"{i}. [{severity_label.upper()}] {trans.get('title', vuln.vulnerability_type or 'Unknown')}",
                ParagraphStyle(
                    f'VulnHeader_{i}',
                    fontSize=11,
                    leading=14,
                    spaceBefore=15,
                    spaceAfter=5,
                    textColor=colors.HexColor(severity_color),
                    fontName=self._font_name,
                )
            ))
            
            if vuln.description:
                desc = trans.get('description', vuln.description[:500])
                desc = self._clean_text(desc)
                story.append(Paragraph(
                    f"<b>Описание:</b> {desc}",
                    self._styles['CustomBody']
                ))
            
            if vuln.evidence:
                evidence = self._clean_text(vuln.evidence[:300])
                story.append(Paragraph(
                    f"<b>Доказательство:</b> {evidence}",
                    self._styles['CustomBody']
                ))
            
            if vuln.remediation:
                remediation = trans.get('remediation', vuln.remediation[:500])
                remediation = self._clean_text(remediation)
                remediation = self._format_numbered_list(remediation)
                story.append(Paragraph(
                    f"<b>Рекомендация:</b><br/>{remediation}",
                    self._styles['CustomBody']
                ))
            
            story.append(Spacer(1, 0.3*cm))
        
        return story
    
    def _translate_vulnerabilities(self, vulns: list[VulnerabilityRecord]) -> dict:
        """Переводит описания уязвимостей на русский через DeepSeek."""
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            logger.warning("DEEPSEEK_API_KEY not set, skipping translation")
            return {}
        
        # Prepare data for translation
        to_translate = []
        for v in vulns:
            to_translate.append({
                "id": str(v.id),
                "title": v.vulnerability_type or "",
                "description": (v.description or "")[:400],
                "remediation": (v.remediation or "")[:400],
            })
        
        if not to_translate:
            return {}
        
        try:
            import httpx
            
            prompt = f"""Переведи на русский язык описания уязвимостей. Сохрани технические термины.
Верни JSON массив с теми же id и переведёнными полями title, description, remediation.

Входные данные:
{json.dumps(to_translate, ensure_ascii=False)}

Отвечай ТОЛЬКО валидным JSON массивом без markdown."""

            response = httpx.post(
                "https://api.deepseek.com/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "deepseek-chat",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                    "max_tokens": 4000,
                },
                timeout=90.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                # Clean markdown if present
                content = content.strip()
                if content.startswith("```"):
                    content = content.split("\n", 1)[1]
                if content.endswith("```"):
                    content = content.rsplit("```", 1)[0]
                
                translated = json.loads(content)
                # Convert to dict by id
                result = {}
                for item in translated:
                    result[item["id"]] = item
                logger.info("Translated %d vulnerabilities", len(result))
                return result
            else:
                logger.error("DeepSeek translation error: %s", response.text)
                return {}
                
        except Exception as e:
            logger.exception("Failed to translate vulnerabilities: %s", e)
            return {}
        
        return story
    
    def _clean_text(self, text: str) -> str:
        """Очищает текст от markdown и спецсимволов для PDF."""
        if not text:
            return ""
        # Remove markdown bold/italic
        text = text.replace('**', '').replace('__', '')
        text = text.replace('*', '').replace('_', ' ')
        # Escape HTML special chars (& must be first!)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        # Remove excessive whitespace
        text = ' '.join(text.split())
        return text
    
    def _clean_command(self, text: str) -> str:
        """Очищает команду от непечатаемых символов для PDF."""
        if not text:
            return ""
        # Keep only printable ASCII and basic Cyrillic
        import re
        # Remove emojis and special unicode
        text = re.sub(r'[^\x20-\x7E\u0400-\u04FF\u0020-\u007F]', '', text)
        # Remove markdown
        text = text.replace('**', '').replace('`', '').replace('*', '')
        # Escape HTML special chars
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        # Clean whitespace
        text = ' '.join(text.split())
        return text.strip()
    
    def _format_numbered_list(self, text: str) -> str:
        """Форматирует нумерованный список с переносами строк."""
        import re
        # Pattern: "1. text 2. text" -> "1. text<br/>2. text"
        # Match number followed by dot and space
        formatted = re.sub(r'\s+(\d+)\.\s+', r'<br/>\1. ', text)
        # Remove leading <br/> if present
        if formatted.startswith('<br/>'):
            formatted = formatted[5:]
        return formatted

    def _create_recommendations_section(
        self,
        vulns: list[VulnerabilityRecord],
        ai_summary: dict | None,
    ) -> list:
        """Создаёт секцию с рекомендациями."""
        story = []
        
        story.append(Paragraph("РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ", self._styles['SectionTitle']))
        
        if ai_summary and "priority_actions" in ai_summary:
            story.append(Paragraph(
                "<b>Приоритетные действия:</b>",
                self._styles['VulnTitle']
            ))
            
            actions = ai_summary["priority_actions"]
            if isinstance(actions, list):
                for i, action in enumerate(actions, 1):
                    clean_action = self._clean_text(action)
                    story.append(Paragraph(
                        f"{i}. {clean_action}",
                        self._styles['CustomBody']
                    ))
        else:
            recommendations = [
                "Немедленно устранить все критические уязвимости",
                "Провести аудит конфигурации веб-сервера",
                "Обновить все компоненты до последних версий",
                "Внедрить WAF (Web Application Firewall)",
                "Настроить мониторинг безопасности",
                "Провести обучение разработчиков по безопасному кодированию",
                "Регулярно проводить тестирование на проникновение",
            ]
            
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(
                    f"{i}. {rec}",
                    self._styles['CustomBody']
                ))
        
        story.append(Spacer(1, 1*cm))
        
        story.append(Paragraph("ЗАКЛЮЧЕНИЕ", self._styles['SectionTitle']))
        story.append(Paragraph(
            """
            Данный отчёт содержит результаты автоматизированного тестирования безопасности.
            Для полной оценки защищённости рекомендуется провести дополнительное ручное 
            тестирование на проникновение.
            <br/><br/>
            При возникновении вопросов по результатам тестирования обращайтесь к специалистам
            по информационной безопасности.
            """,
            self._styles['CustomBody']
        ))
        
        return story

    # ==================== NEW AI-POWERED METHODS ====================
    
    def _create_executive_summary_ai(
        self,
        stats: dict,
        ai_analysis: dict | None,
        company_name: str,
        industry: str,
    ) -> list:
        """Создаёт AI-генерируемое Executive Summary."""
        story = []
        
        story.append(Paragraph("РЕЗЮМЕ ДЛЯ РУКОВОДСТВА", self._styles['SectionTitle']))
        
        if ai_analysis and "executive_summary" in ai_analysis:
            summary = self._clean_text(ai_analysis["executive_summary"])
            story.append(Paragraph(summary, self._styles['CustomBody']))
        else:
            # Fallback
            critical_high = stats["critical"] + stats["high"]
            risk_level = "КРИТИЧЕСКИЙ" if stats["critical"] > 0 else "ВЫСОКИЙ" if stats["high"] > 0 else "СРЕДНИЙ"
            story.append(Paragraph(
                f"В ходе тестирования обнаружено {stats['total']} уязвимостей. "
                f"Уровень риска: {risk_level}.",
                self._styles['CustomBody']
            ))
        
        # Risk level badge
        if ai_analysis and "risk_level" in ai_analysis:
            risk_level = ai_analysis["risk_level"]
            risk_colors = {
                "КРИТИЧЕСКИЙ": "#DC2626",
                "ВЫСОКИЙ": "#EA580C", 
                "СРЕДНИЙ": "#CA8A04",
                "НИЗКИЙ": "#22C55E",
            }
            color = risk_colors.get(risk_level, "#6B7280")
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph(
                f"<b>Уровень риска: <font color='{color}'>{risk_level}</font></b>",
                self._styles['VulnTitle']
            ))
        
        # Score
        if ai_analysis and "overall_score" in ai_analysis:
            score = ai_analysis["overall_score"]
            story.append(Paragraph(
                f"<b>Оценка безопасности: {score}/10</b>",
                self._styles['VulnTitle']
            ))
        
        # Industry-specific risks
        if ai_analysis and "industry_specific_risks" in ai_analysis:
            story.append(Spacer(1, 0.5*cm))
            industry_info = INDUSTRY_INFO.get(industry, INDUSTRY_INFO["general"])
            story.append(Paragraph(
                f"<b>Специфические риски для отрасли «{industry_info['name']}»</b>",
                self._styles['VulnTitle']
            ))
            risks = self._clean_text(ai_analysis["industry_specific_risks"])
            story.append(Paragraph(risks, self._styles['CustomBody']))
        
        return story

    def _create_business_impact_section_ai(
        self,
        stats: dict,
        vulns: list[VulnerabilityRecord],
        ai_analysis: dict | None,
        industry: str,
    ) -> list:
        """Создаёт AI-улучшенную секцию бизнес-влияния."""
        story = []
        
        story.append(Paragraph("ОЦЕНКА БИЗНЕС-ВЛИЯНИЯ", self._styles['SectionTitle']))
        
        # Attack scenarios from AI
        if ai_analysis and "attack_scenarios" in ai_analysis:
            story.append(Paragraph("<b>Сценарии атак (на основе найденных уязвимостей)</b>", self._styles['VulnTitle']))
            story.append(Spacer(1, 0.2*cm))
            
            scenarios = ai_analysis["attack_scenarios"]
            if isinstance(scenarios, list):
                for scenario in scenarios[:5]:
                    name = self._clean_text(scenario.get("name", ""))
                    desc = self._clean_text(scenario.get("description", ""))
                    impact = self._clean_text(scenario.get("impact", ""))
                    prob = scenario.get("probability", "СРЕДНЯЯ")
                    
                    prob_colors = {"ВЫСОКАЯ": "#DC2626", "СРЕДНЯЯ": "#CA8A04", "НИЗКАЯ": "#22C55E"}
                    prob_color = prob_colors.get(prob, "#6B7280")
                    
                    story.append(Paragraph(
                        f"• <b>{name}</b> [<font color='{prob_color}'>{prob}</font>]<br/>"
                        f"{desc}<br/>"
                        f"<i>Последствия: {impact}</i>",
                        self._styles['CustomBody']
                    ))
                    story.append(Spacer(1, 0.2*cm))
        
        story.append(Spacer(1, 0.5*cm))
        
        # Compliance violations from AI
        if ai_analysis and "compliance_violations" in ai_analysis:
            story.append(Paragraph("<b>Нарушения требований законодательства</b>", self._styles['VulnTitle']))
            story.append(Spacer(1, 0.2*cm))
            
            violations = ai_analysis["compliance_violations"]
            if isinstance(violations, list) and violations:
                # Create cell style for wrapping text
                cell_style = ParagraphStyle(
                    'TableCell',
                    fontSize=8,
                    leading=10,
                    fontName=self._font_name,
                    textColor=colors.HexColor("#374151"),
                )
                header_style = ParagraphStyle(
                    'TableHeader',
                    fontSize=9,
                    leading=11,
                    fontName=self._font_name,
                    textColor=colors.white,
                )
                
                violation_data = [
                    [
                        Paragraph("<b>Требование</b>", header_style),
                        Paragraph("<b>Нарушение</b>", header_style),
                        Paragraph("<b>Санкции</b>", header_style),
                    ]
                ]
                for v in violations[:6]:
                    violation_data.append([
                        Paragraph(self._clean_text(v.get("regulation", "")), cell_style),
                        Paragraph(self._clean_text(v.get("violation", "")), cell_style),
                        Paragraph(self._clean_text(v.get("penalty", "")), cell_style),
                    ])
                
                violation_table = Table(violation_data, colWidths=[4.5*cm, 6*cm, 6*cm])
                violation_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#DC2626")),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#FEF2F2")),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#FECACA")),
                ]))
                story.append(violation_table)
        else:
            story.append(Paragraph(
                "На основании анализа существенных нарушений законодательства не выявлено.",
                self._styles['CustomBody']
            ))
        
        return story

    def _create_charts_section_ai(self, stats: dict, ai_analysis: dict | None) -> list:
        """Создаёт секцию с графиками и AI-анализом трендов."""
        story = []
        
        story.append(Paragraph("ВИЗУАЛИЗАЦИЯ РЕЗУЛЬТАТОВ", self._styles['SectionTitle']))
        
        # Pie chart
        pie_chart = self._create_severity_pie_chart(stats)
        if pie_chart:
            story.append(Image(pie_chart, width=12*cm, height=12*cm))
        
        story.append(Spacer(1, 0.5*cm))
        
        # AI chart analysis
        if ai_analysis and "chart_analysis" in ai_analysis:
            story.append(Paragraph("<b>Анализ распределения</b>", self._styles['VulnTitle']))
            analysis = self._clean_text(ai_analysis["chart_analysis"])
            story.append(Paragraph(analysis, self._styles['CustomBody']))
        
        story.append(Spacer(1, 1*cm))
        
        # Bar chart
        if stats["by_type"]:
            bar_chart = self._create_type_bar_chart(stats["by_type"])
            if bar_chart:
                story.append(Image(bar_chart, width=16*cm, height=10*cm))
        
        return story

    def _create_vulnerabilities_section_ai(
        self,
        vulns: list[VulnerabilityRecord],
        ai_analysis: dict | None,
    ) -> list:
        """Создаёт секцию уязвимостей с AI-описаниями."""
        story = []
        
        story.append(Paragraph("ДЕТАЛЬНОЕ ОПИСАНИЕ УЯЗВИМОСТЕЙ", self._styles['SectionTitle']))
        
        # Get AI-generated vulnerability analysis
        ai_vulns = {}
        if ai_analysis and "vulnerabilities_analysis" in ai_analysis:
            for av in ai_analysis["vulnerabilities_analysis"]:
                vtype = av.get("type", "")
                ai_vulns[vtype] = av
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        sorted_vulns = sorted(
            vulns,
            key=lambda v: severity_order.get(v.severity.lower() if v.severity else "informational", 5)
        )
        
        for i, vuln in enumerate(sorted_vulns[:30], 1):
            severity = vuln.severity.lower() if vuln.severity else "informational"
            severity_color = SEVERITY_COLORS.get(severity, "#6B7280")
            severity_label = SEVERITY_LABELS_RU.get(severity, severity.upper())
            
            # Try to get AI analysis for this vulnerability type
            ai_vuln = ai_vulns.get(vuln.vulnerability_type, {})
            
            title = ai_vuln.get("title_ru", vuln.vulnerability_type or "Unknown")
            story.append(Paragraph(
                f"{i}. [{severity_label.upper()}] {title}",
                ParagraphStyle(
                    f'VulnHeaderAI_{i}',
                    fontSize=11,
                    leading=14,
                    spaceBefore=15,
                    spaceAfter=5,
                    textColor=colors.HexColor(severity_color),
                    fontName=self._font_name,
                )
            ))
            
            # Description
            desc = ai_vuln.get("description_ru") or vuln.description
            if desc:
                desc = self._clean_text(desc[:500])
                story.append(Paragraph(f"<b>Описание:</b> {desc}", self._styles['CustomBody']))
            
            # Business impact from AI
            if ai_vuln.get("business_impact"):
                impact = self._clean_text(ai_vuln["business_impact"])
                story.append(Paragraph(f"<b>Влияние на бизнес:</b> {impact}", self._styles['CustomBody']))
            
            # Evidence
            if vuln.evidence:
                evidence = self._clean_text(vuln.evidence[:200])
                story.append(Paragraph(f"<b>Доказательство:</b> {evidence}", self._styles['CustomBody']))
            
            # Remediation from AI or original
            remediation = ai_vuln.get("remediation_ru") or vuln.remediation
            if remediation:
                remediation = self._clean_text(remediation[:500])
                remediation = self._format_numbered_list(remediation)
                story.append(Paragraph(f"<b>Рекомендация:</b><br/>{remediation}", self._styles['CustomBody']))
            
            story.append(Spacer(1, 0.3*cm))
        
        return story

    def _create_recommendations_section_ai(
        self,
        vulns: list[VulnerabilityRecord],
        ai_analysis: dict | None,
    ) -> list:
        """Создаёт AI-генерируемую секцию рекомендаций с конкретными шагами."""
        story = []
        
        story.append(Paragraph("ПЛАН УСТРАНЕНИЯ УЯЗВИМОСТЕЙ", self._styles['SectionTitle']))
        
        if ai_analysis and "remediation_steps" in ai_analysis:
            steps = ai_analysis["remediation_steps"]
            if isinstance(steps, list):
                for step in steps[:10]:
                    priority = step.get("priority", "")
                    title = self._clean_text(step.get("title", ""))
                    description = self._clean_text(step.get("description", ""))
                    timeline = step.get("timeline", "")
                    responsible = step.get("responsible", "")
                    commands = step.get("commands", [])
                    
                    # Priority color
                    if priority <= 2:
                        prio_color = "#DC2626"
                        prio_label = "СРОЧНО"
                    elif priority <= 4:
                        prio_color = "#EA580C"
                        prio_label = "ВЫСОКИЙ"
                    else:
                        prio_color = "#CA8A04"
                        prio_label = "СРЕДНИЙ"
                    
                    story.append(Paragraph(
                        f"<b>{priority}. {title}</b> [<font color='{prio_color}'>{prio_label}</font>]",
                        self._styles['VulnTitle']
                    ))
                    
                    story.append(Paragraph(description, self._styles['CustomBody']))
                    
                    # Commands
                    if commands and isinstance(commands, list):
                        story.append(Paragraph("<b>Команды:</b>", self._styles['CustomBody']))
                        for cmd in commands[:5]:
                            cmd_clean = self._clean_command(cmd)
                            if cmd_clean:
                                story.append(Paragraph(
                                    f"<font face='{self._font_name}' size='9' color='#1E40AF'><b>{cmd_clean}</b></font>",
                                    self._styles['CustomBody']
                                ))
                    
                    # Timeline and responsible
                    if timeline or responsible:
                        meta = []
                        if timeline:
                            meta.append(f"Срок: {timeline}")
                        if responsible:
                            meta.append(f"Ответственный: {responsible}")
                        story.append(Paragraph(
                            f"<i>{' | '.join(meta)}</i>",
                            self._styles['CustomBody']
                        ))
                    
                    story.append(Spacer(1, 0.3*cm))
        else:
            # Fallback recommendations
            story.append(Paragraph(
                "1. Немедленно устранить критические уязвимости<br/>"
                "2. Провести аудит конфигурации<br/>"
                "3. Обновить все компоненты<br/>"
                "4. Внедрить WAF<br/>"
                "5. Настроить мониторинг",
                self._styles['CustomBody']
            ))
        
        story.append(Spacer(1, 1*cm))
        
        story.append(Paragraph("ЗАКЛЮЧЕНИЕ", self._styles['SectionTitle']))
        story.append(Paragraph(
            "Данный отчёт сгенерирован с использованием искусственного интеллекта на основе "
            "результатов автоматизированного сканирования. Все выводы и рекомендации основаны "
            "исключительно на обнаруженных уязвимостях.<br/><br/>"
            "Для полной оценки защищённости рекомендуется провести дополнительное ручное "
            "тестирование на проникновение.",
            self._styles['CustomBody']
        ))
        
        return story

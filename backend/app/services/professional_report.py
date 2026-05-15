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
        include_executive_summary: bool = True,
        use_ai_descriptions: bool = True,
    ) -> bytes:
        """Генерирует профессиональный PDF-отчёт."""
        logger.info("Generating professional report for scan %s", scan_id)
        
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        asset = self.db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
        target_url = asset.target if asset else "Unknown"
        
        vulns = self.db.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan_id
        ).all()
        
        stats = self._calculate_stats(vulns)
        
        # AI Summary
        ai_summary = None
        if use_ai_descriptions:
            ai_summary = self._generate_ai_summary(vulns, target_url, company_name)
        
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
        story.extend(self._create_title_page(company_name, target_url, scan, stats))
        story.append(PageBreak())
        
        # Executive Summary
        if include_executive_summary:
            story.extend(self._create_executive_summary(stats, ai_summary, company_name))
            story.append(PageBreak())
        
        # Charts
        story.extend(self._create_charts_section(stats))
        story.append(PageBreak())
        
        # Vulnerabilities
        story.extend(self._create_vulnerabilities_section(vulns))
        
        # Recommendations
        story.append(PageBreak())
        story.extend(self._create_recommendations_section(vulns, ai_summary))
        
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

    def _generate_ai_summary(
        self,
        vulns: list[VulnerabilityRecord],
        target_url: str,
        company_name: str,
    ) -> dict | None:
        """Генерирует AI-описания через DeepSeek V4 Pro."""
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            logger.warning("DEEPSEEK_API_KEY not set, skipping AI summary")
            return None
        
        try:
            import httpx
            
            vuln_list = []
            for v in vulns[:20]:
                vuln_list.append({
                    "type": v.vulnerability_type,
                    "severity": v.severity,
                    "description": v.description[:200] if v.description else "",
                })
            
            prompt = f"""Ты — эксперт по кибербезопасности. Создай профессиональный отчёт для клиента НА РУССКОМ ЯЗЫКЕ.

Цель: {target_url}
Компания: {company_name}
Найденные уязвимости: {json.dumps(vuln_list, ensure_ascii=False)}

Сгенерируй JSON с полями (ВСЕ ТЕКСТЫ НА РУССКОМ):
1. "executive_summary" — краткое резюме для руководства (2-3 абзаца на русском)
2. "risk_assessment" — оценка бизнес-рисков на русском (что может произойти если не исправить)
3. "priority_actions" — список из 5 приоритетных действий на русском
4. "overall_score" — оценка безопасности от 1 до 10 (10 = отлично)

Отвечай ТОЛЬКО валидным JSON без markdown."""

            response = httpx.post(
                "https://api.deepseek.com/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "deepseek-v4-pro",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 2000,
                },
                timeout=60.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                return json.loads(content)
            else:
                logger.error("DeepSeek API error: %s", response.text)
                return None
                
        except Exception as e:
            logger.exception("Failed to generate AI summary: %s", e)
            return None

    def _create_title_page(
        self,
        company_name: str,
        target_url: str,
        scan: Scan,
        stats: dict,
    ) -> list:
        """Создаёт титульную страницу."""
        story = []
        
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph(
            "ОТЧЁТ О ТЕСТИРОВАНИИ<br/>БЕЗОПАСНОСТИ",
            self._styles['ReportTitle']
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
            story.append(Paragraph(ai_summary["executive_summary"], self._styles['CustomBody']))
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
            story.append(Paragraph(ai_summary["risk_assessment"], self._styles['CustomBody']))
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

    def _create_charts_section(self, stats: dict) -> list:
        """Создаёт секцию с графиками."""
        story = []
        
        story.append(Paragraph("ВИЗУАЛИЗАЦИЯ РЕЗУЛЬТАТОВ", self._styles['SectionTitle']))
        
        # Pie chart
        pie_chart = self._create_severity_pie_chart(stats)
        if pie_chart:
            story.append(Image(pie_chart, width=14*cm, height=10*cm))
        
        story.append(Spacer(1, 1*cm))
        
        # Bar chart
        if stats["by_type"]:
            bar_chart = self._create_type_bar_chart(stats["by_type"])
            if bar_chart:
                story.append(Image(bar_chart, width=14*cm, height=8*cm))
        
        return story

    def _create_severity_pie_chart(self, stats: dict) -> io.BytesIO | None:
        """Создаёт pie chart."""
        try:
            labels = []
            sizes = []
            colors_list = []
            
            for severity in ["critical", "high", "medium", "low", "informational"]:
                if stats[severity] > 0:
                    labels.append(f"{SEVERITY_LABELS_RU[severity]} ({stats[severity]})")
                    sizes.append(stats[severity])
                    colors_list.append(SEVERITY_COLORS[severity])
            
            if not sizes:
                return None
            
            # Use font that supports Cyrillic
            plt.rcParams['font.family'] = ['DejaVu Sans', 'sans-serif']
            
            fig, ax = plt.subplots(figsize=(8, 6))
            
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors_list,
                autopct='%1.1f%%',
                startangle=90,
                explode=[0.02] * len(sizes),
            )
            
            ax.set_title('Распределение уязвимостей по критичности', fontsize=14, fontweight='bold')
            
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            
            plt.tight_layout()
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close(fig)
            buf.seek(0)
            
            return buf
            
        except Exception as e:
            logger.exception("Failed to create pie chart: %s", e)
            return None

    def _create_type_bar_chart(self, by_type: dict) -> io.BytesIO | None:
        """Создаёт bar chart по типам."""
        try:
            sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]
            
            if not sorted_types:
                return None
            
            labels = [t[0][:30] for t in sorted_types]
            values = [t[1] for t in sorted_types]
            
            plt.rcParams['font.family'] = ['DejaVu Sans', 'sans-serif']
            
            fig, ax = plt.subplots(figsize=(10, 6))
            
            bars = ax.barh(labels, values, color='#3B82F6')
            
            ax.set_xlabel('Количество')
            ax.set_title('Топ-10 типов уязвимостей', fontsize=14, fontweight='bold')
            
            for bar, value in zip(bars, values):
                ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                       str(value), va='center', fontsize=10)
            
            plt.tight_layout()
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
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
        
        for i, vuln in enumerate(sorted_vulns[:30], 1):
            severity = vuln.severity.lower() if vuln.severity else "informational"
            severity_color = SEVERITY_COLORS.get(severity, "#6B7280")
            severity_label = SEVERITY_LABELS_RU.get(severity, severity.upper())
            
            story.append(Paragraph(
                f"{i}. [{severity_label.upper()}] {vuln.vulnerability_type or 'Unknown'}",
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
                desc = vuln.description[:500].replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph(
                    f"<b>Описание:</b> {desc}",
                    self._styles['CustomBody']
                ))
            
            if vuln.evidence:
                evidence = vuln.evidence[:300].replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph(
                    f"<b>Доказательство:</b> {evidence}",
                    self._styles['CustomBody']
                ))
            
            if vuln.remediation:
                remediation = vuln.remediation[:300].replace('<', '&lt;').replace('>', '&gt;')
                story.append(Paragraph(
                    f"<b>Рекомендация:</b> {remediation}",
                    self._styles['CustomBody']
                ))
            
            story.append(Spacer(1, 0.3*cm))
        
        return story

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
                    story.append(Paragraph(
                        f"{i}. {action}",
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

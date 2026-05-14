"""Профессиональный генератор PDF-отчётов с графиками.

Создаёт красивые PDF-отчёты для клиентов с:
- Executive Summary
- Графиками распределения уязвимостей
- Детальным описанием каждой уязвимости
- Оценкой бизнес-рисков
- Рекомендациями по устранению

Использует DeepSeek V3 для генерации текстов.
"""

from __future__ import annotations

import io
import json
import logging
import os
from datetime import datetime, UTC
from typing import Any

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, ListFlowable, ListItem
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from sqlalchemy.orm import Session

from app.models.database import VulnerabilityRecord, Scan
from app.models.database import Asset as AssetDB

logger = logging.getLogger(__name__)

# Цвета для severity
SEVERITY_COLORS = {
    "critical": "#DC2626",  # Red
    "high": "#EA580C",      # Orange
    "medium": "#CA8A04",    # Yellow
    "low": "#2563EB",       # Blue
    "informational": "#6B7280",  # Gray
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
        self._styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Настройка стилей для PDF."""
        # Заголовок отчёта
        self._styles.add(ParagraphStyle(
            name='ReportTitle',
            fontSize=24,
            leading=30,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor("#1E293B"),
            fontName='Helvetica-Bold',
        ))
        
        # Подзаголовок
        self._styles.add(ParagraphStyle(
            name='SectionTitle',
            fontSize=16,
            leading=20,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor("#1E40AF"),
            fontName='Helvetica-Bold',
        ))
        
        # Обычный текст
        self._styles.add(ParagraphStyle(
            name='BodyText',
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            spaceAfter=8,
            textColor=colors.HexColor("#374151"),
        ))
        
        # Текст уязвимости
        self._styles.add(ParagraphStyle(
            name='VulnTitle',
            fontSize=12,
            leading=16,
            spaceBefore=15,
            spaceAfter=5,
            textColor=colors.HexColor("#1E293B"),
            fontName='Helvetica-Bold',
        ))

    def generate_report(
        self,
        scan_id: str,
        company_name: str = "Клиент",
        include_executive_summary: bool = True,
        use_ai_descriptions: bool = True,
    ) -> bytes:
        """Генерирует профессиональный PDF-отчёт.
        
        Args:
            scan_id: ID сканирования
            company_name: Название компании клиента
            include_executive_summary: Включить Executive Summary
            use_ai_descriptions: Использовать AI для генерации описаний
            
        Returns:
            PDF-файл в виде bytes
        """
        # Получаем данные сканирования
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Получаем актив
        asset = self.db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
        target_url = asset.target if asset else "Unknown"
        
        # Получаем уязвимости
        vulns = self.db.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan_id
        ).all()
        
        # Статистика
        stats = self._calculate_stats(vulns)
        
        # Генерируем AI-описания если нужно
        ai_summary = None
        if use_ai_descriptions:
            ai_summary = self._generate_ai_summary(vulns, target_url, company_name)
        
        # Создаём PDF
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
        
        # Титульная страница
        story.extend(self._create_title_page(company_name, target_url, scan, stats))
        story.append(PageBreak())
        
        # Executive Summary
        if include_executive_summary:
            story.extend(self._create_executive_summary(stats, ai_summary, company_name))
            story.append(PageBreak())
        
        # Графики
        story.extend(self._create_charts_section(stats))
        story.append(PageBreak())
        
        # Детальные уязвимости
        story.extend(self._create_vulnerabilities_section(vulns, use_ai_descriptions))
        
        # Рекомендации
        story.append(PageBreak())
        story.extend(self._create_recommendations_section(vulns, ai_summary))
        
        # Собираем PDF
        doc.build(story)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes

    def _calculate_stats(self, vulns: list[VulnerabilityRecord]) -> dict:
        """Подсчёт статистики уязвимостей."""
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
        """Генерирует AI-описания через DeepSeek."""
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            logger.warning("DEEPSEEK_API_KEY not set, skipping AI summary")
            return None
        
        try:
            import httpx
            
            # Формируем список уязвимостей для AI
            vuln_list = []
            for v in vulns[:20]:  # Ограничиваем для экономии токенов
                vuln_list.append({
                    "type": v.vulnerability_type,
                    "severity": v.severity,
                    "description": v.description[:200] if v.description else "",
                })
            
            prompt = f"""Ты — эксперт по кибербезопасности. Создай профессиональный отчёт для клиента.

Цель: {target_url}
Компания: {company_name}
Найденные уязвимости: {json.dumps(vuln_list, ensure_ascii=False)}

Сгенерируй JSON с полями:
1. "executive_summary" — краткое резюме для руководства (2-3 абзаца на русском)
2. "risk_assessment" — оценка бизнес-рисков (что может произойти если не исправить)
3. "priority_actions" — список из 5 приоритетных действий
4. "overall_score" — оценка безопасности от 1 до 10 (10 = отлично)

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
                    "max_tokens": 2000,
                },
                timeout=60.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                # Парсим JSON из ответа
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
        
        # Заголовок
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph(
            "ОТЧЁТ О ТЕСТИРОВАНИИ<br/>БЕЗОПАСНОСТИ",
            self._styles['ReportTitle']
        ))
        
        story.append(Spacer(1, 1*cm))
        
        # Информация о клиенте
        story.append(Paragraph(
            f"<b>Клиент:</b> {company_name}",
            self._styles['BodyText']
        ))
        story.append(Paragraph(
            f"<b>Цель тестирования:</b> {target_url}",
            self._styles['BodyText']
        ))
        story.append(Paragraph(
            f"<b>Дата сканирования:</b> {scan.started_at.strftime('%d.%m.%Y %H:%M') if scan.started_at else 'N/A'}",
            self._styles['BodyText']
        ))
        
        story.append(Spacer(1, 2*cm))
        
        # Краткая статистика
        summary_data = [
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
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F1F5F9")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ]))
        
        story.append(summary_table)
        
        story.append(Spacer(1, 3*cm))
        
        # Конфиденциальность
        story.append(Paragraph(
            "<b>КОНФИДЕНЦИАЛЬНО</b><br/>"
            "Данный отчёт содержит конфиденциальную информацию и предназначен "
            "исключительно для внутреннего использования.",
            ParagraphStyle(
                'Confidential',
                fontSize=9,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#DC2626"),
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
        
        story.append(Paragraph("EXECUTIVE SUMMARY", self._styles['SectionTitle']))
        
        if ai_summary and "executive_summary" in ai_summary:
            story.append(Paragraph(ai_summary["executive_summary"], self._styles['BodyText']))
        else:
            # Fallback текст
            critical_high = stats["critical"] + stats["high"]
            risk_level = "ВЫСОКИЙ" if critical_high > 0 else "СРЕДНИЙ" if stats["medium"] > 0 else "НИЗКИЙ"
            
            summary_text = f"""
            В ходе тестирования безопасности было обнаружено <b>{stats['total']}</b> уязвимостей, 
            из которых <b>{stats['critical']}</b> критических и <b>{stats['high']}</b> высокой степени серьёзности.
            
            Общий уровень риска оценивается как <b>{risk_level}</b>.
            
            Рекомендуется незамедлительно устранить критические и высокие уязвимости для 
            предотвращения потенциальных инцидентов безопасности.
            """
            story.append(Paragraph(summary_text, self._styles['BodyText']))
        
        # Оценка рисков
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("Оценка бизнес-рисков", self._styles['VulnTitle']))
        
        if ai_summary and "risk_assessment" in ai_summary:
            story.append(Paragraph(ai_summary["risk_assessment"], self._styles['BodyText']))
        else:
            risk_text = """
            Обнаруженные уязвимости могут привести к:
            • Несанкционированному доступу к конфиденциальным данным
            • Компрометации учётных записей пользователей
            • Финансовым потерям и репутационному ущербу
            • Нарушению требований регуляторов (GDPR, 152-ФЗ)
            """
            story.append(Paragraph(risk_text, self._styles['BodyText']))
        
        # Оценка безопасности
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
        
        # Pie chart уязвимостей по severity
        pie_chart = self._create_severity_pie_chart(stats)
        if pie_chart:
            story.append(Image(pie_chart, width=14*cm, height=10*cm))
        
        story.append(Spacer(1, 1*cm))
        
        # Bar chart по типам
        if stats["by_type"]:
            bar_chart = self._create_type_bar_chart(stats["by_type"])
            if bar_chart:
                story.append(Image(bar_chart, width=14*cm, height=8*cm))
        
        return story

    def _create_severity_pie_chart(self, stats: dict) -> io.BytesIO | None:
        """Создаёт pie chart распределения по severity."""
        try:
            # Данные для графика
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
            
            fig, ax = plt.subplots(figsize=(8, 6))
            
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors_list,
                autopct='%1.1f%%',
                startangle=90,
                explode=[0.02] * len(sizes),
            )
            
            ax.set_title('Распределение уязвимостей по серьёзности', fontsize=14, fontweight='bold')
            
            # Улучшаем читаемость
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            
            plt.tight_layout()
            
            # Сохраняем в буфер
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close(fig)
            buf.seek(0)
            
            return buf
            
        except Exception as e:
            logger.exception("Failed to create pie chart: %s", e)
            return None

    def _create_type_bar_chart(self, by_type: dict) -> io.BytesIO | None:
        """Создаёт bar chart по типам уязвимостей."""
        try:
            # Берём топ-10 типов
            sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]
            
            if not sorted_types:
                return None
            
            labels = [t[0][:30] for t in sorted_types]  # Обрезаем длинные названия
            values = [t[1] for t in sorted_types]
            
            fig, ax = plt.subplots(figsize=(10, 6))
            
            bars = ax.barh(labels, values, color='#3B82F6')
            
            ax.set_xlabel('Количество')
            ax.set_title('Топ-10 типов уязвимостей', fontsize=14, fontweight='bold')
            
            # Добавляем значения на бары
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

    def _create_vulnerabilities_section(
        self,
        vulns: list[VulnerabilityRecord],
        use_ai: bool,
    ) -> list:
        """Создаёт секцию с детальными уязвимостями."""
        story = []
        
        story.append(Paragraph("ДЕТАЛЬНОЕ ОПИСАНИЕ УЯЗВИМОСТЕЙ", self._styles['SectionTitle']))
        
        # Сортируем по severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        sorted_vulns = sorted(
            vulns,
            key=lambda v: severity_order.get(v.severity.lower() if v.severity else "informational", 5)
        )
        
        for i, vuln in enumerate(sorted_vulns[:30], 1):  # Ограничиваем 30 уязвимостями
            severity = vuln.severity.lower() if vuln.severity else "informational"
            severity_color = SEVERITY_COLORS.get(severity, "#6B7280")
            severity_label = SEVERITY_LABELS_RU.get(severity, severity.upper())
            
            # Заголовок уязвимости
            story.append(Paragraph(
                f"{i}. [{severity_label.upper()}] {vuln.vulnerability_type or 'Unknown'}",
                ParagraphStyle(
                    'VulnHeader',
                    fontSize=11,
                    leading=14,
                    spaceBefore=15,
                    spaceAfter=5,
                    textColor=colors.HexColor(severity_color),
                    fontName='Helvetica-Bold',
                )
            ))
            
            # Описание
            if vuln.description:
                story.append(Paragraph(
                    f"<b>Описание:</b> {vuln.description[:500]}",
                    self._styles['BodyText']
                ))
            
            # Evidence
            if vuln.evidence:
                story.append(Paragraph(
                    f"<b>Доказательство:</b> {vuln.evidence[:300]}",
                    self._styles['BodyText']
                ))
            
            # Impact
            if vuln.impact_assessment:
                story.append(Paragraph(
                    f"<b>Влияние:</b> {vuln.impact_assessment[:300]}",
                    self._styles['BodyText']
                ))
            
            # Remediation
            if vuln.remediation:
                story.append(Paragraph(
                    f"<b>Рекомендация:</b> {vuln.remediation[:300]}",
                    self._styles['BodyText']
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
                        self._styles['BodyText']
                    ))
        else:
            # Fallback рекомендации
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
                    self._styles['BodyText']
                ))
        
        story.append(Spacer(1, 1*cm))
        
        # Заключение
        story.append(Paragraph("ЗАКЛЮЧЕНИЕ", self._styles['SectionTitle']))
        story.append(Paragraph(
            """
            Данный отчёт содержит результаты автоматизированного тестирования безопасности.
            Для полной оценки защищённости рекомендуется провести дополнительное ручное 
            тестирование на проникновение.
            
            При возникновении вопросов по результатам тестирования обращайтесь к специалистам
            по информационной безопасности.
            """,
            self._styles['BodyText']
        ))
        
        return story

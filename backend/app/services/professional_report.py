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

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

from sqlalchemy.orm import Session

from app.models.database import VulnerabilityRecord, Scan
from app.models.database import Asset as AssetDB

logger = logging.getLogger(__name__)

# Цвета для severity
SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "informational": "#6B7280",
}

SEVERITY_LABELS_RU = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
}

# Транслитерация для PDF (Helvetica не поддерживает кириллицу)
TRANSLIT_MAP = {
    "Критические": "Critical", "Высокие": "High", "Средние": "Medium",
    "Низкие": "Low", "Информационные": "Info",
    "уязвимостей": "vulnerabilities", "уязвимости": "vulnerabilities",
    "Уязвимость": "Vulnerability", "Описание": "Description",
    "Рекомендации": "Recommendations", "Отчёт": "Report",
    "Клиент": "Client", "Цель": "Target", "Дата": "Date",
    "Всего": "Total", "Критических": "Critical", "Высоких": "High",
    "Средних": "Medium", "Низких": "Low",
}


def transliterate(text: str) -> str:
    """Заменяет кириллицу на латиницу для PDF."""
    if not text:
        return ""
    result = str(text)
    for ru, en in TRANSLIT_MAP.items():
        result = result.replace(ru, en)
    # Удаляем оставшуюся кириллицу
    result = ''.join(c if ord(c) < 128 else '?' for c in result)
    return result


class ProfessionalReportGenerator:
    """Генератор профессиональных PDF-отчётов."""

    def __init__(self, db: Session):
        self.db = db
        self._styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Настройка стилей для PDF."""
        # Проверяем существование стилей перед добавлением
        if 'ReportTitle' not in self._styles.byName:
            self._styles.add(ParagraphStyle(
                name='ReportTitle',
                fontSize=24,
                leading=30,
                alignment=TA_CENTER,
                spaceAfter=20,
                textColor=colors.HexColor("#1E293B"),
                fontName='Helvetica-Bold',
            ))
        
        if 'SectionTitle' not in self._styles.byName:
            self._styles.add(ParagraphStyle(
                name='SectionTitle',
                fontSize=16,
                leading=20,
                spaceBefore=20,
                spaceAfter=10,
                textColor=colors.HexColor("#1E40AF"),
                fontName='Helvetica-Bold',
            ))
        
        # BodyText уже существует в стандартных стилях, используем CustomBody
        if 'CustomBody' not in self._styles.byName:
            self._styles.add(ParagraphStyle(
                name='CustomBody',
                fontSize=10,
                leading=14,
                alignment=TA_JUSTIFY,
                spaceAfter=8,
                textColor=colors.HexColor("#374151"),
            ))
        
        if 'VulnTitle' not in self._styles.byName:
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
        company_name: str = "Client",
        include_executive_summary: bool = True,
        use_ai_descriptions: bool = True,
    ) -> bytes:
        """Генерирует профессиональный PDF-отчёт."""
        logger.info("Generating professional report for scan %s", scan_id)
        
        # Получаем данные сканирования
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Получаем URL цели
        target_url = "Unknown"
        if scan.asset_id:
            asset = self.db.query(AssetDB).filter(AssetDB.id == scan.asset_id).first()
            if asset:
                target_url = asset.target or "Unknown"
        
        # Получаем уязвимости
        vulns = self.db.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan_id
        ).all()
        
        logger.info("Found %d vulnerabilities for report", len(vulns))
        
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
        try:
            story.extend(self._create_charts_section(stats))
            story.append(PageBreak())
        except Exception as e:
            logger.warning("Failed to create charts: %s", e)
        
        # Детальные уязвимости
        story.extend(self._create_vulnerabilities_section(vulns))
        
        # Рекомендации
        story.append(PageBreak())
        story.extend(self._create_recommendations_section(vulns, ai_summary))
        
        # Собираем PDF
        doc.build(story)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        logger.info("Report generated successfully, size: %d bytes", len(pdf_bytes))
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
            severity = (v.severity or "informational").lower()
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
            for v in vulns[:20]:
                vuln_list.append({
                    "type": v.vulnerability_type,
                    "severity": v.severity,
                    "description": (v.description or "")[:200],
                })
            
            prompt = f"""You are a cybersecurity expert. Create a professional security report summary.

Target: {target_url}
Company: {company_name}
Vulnerabilities found: {json.dumps(vuln_list, ensure_ascii=False)}

Generate JSON with fields:
1. "executive_summary" - brief summary for executives (2-3 paragraphs in English)
2. "risk_assessment" - business risk assessment (what could happen if not fixed)
3. "priority_actions" - list of 5 priority actions
4. "overall_score" - security score from 1 to 10 (10 = excellent)

Reply ONLY with valid JSON, no markdown."""

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
                # Убираем markdown если есть
                if "```" in content:
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                return json.loads(content.strip())
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
            "SECURITY ASSESSMENT<br/>REPORT",
            self._styles['ReportTitle']
        ))
        
        story.append(Spacer(1, 1*cm))
        
        story.append(Paragraph(
            f"<b>Client:</b> {transliterate(company_name)}",
            self._styles['CustomBody']
        ))
        story.append(Paragraph(
            f"<b>Target:</b> {target_url}",
            self._styles['CustomBody']
        ))
        
        scan_date = "N/A"
        if scan.started_at:
            scan_date = scan.started_at.strftime('%Y-%m-%d %H:%M')
        story.append(Paragraph(
            f"<b>Scan Date:</b> {scan_date}",
            self._styles['CustomBody']
        ))
        
        story.append(Spacer(1, 2*cm))
        
        # Краткая статистика
        summary_data = [
            ["Metric", "Count"],
            ["Total Vulnerabilities", str(stats["total"])],
            ["Critical", str(stats["critical"])],
            ["High", str(stats["high"])],
            ["Medium", str(stats["medium"])],
            ["Low", str(stats["low"])],
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
        
        story.append(Paragraph(
            "<b>CONFIDENTIAL</b><br/>"
            "This report contains confidential information and is intended "
            "for internal use only.",
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
            text = transliterate(ai_summary["executive_summary"])
            story.append(Paragraph(text, self._styles['CustomBody']))
        else:
            critical_high = stats["critical"] + stats["high"]
            risk_level = "HIGH" if critical_high > 0 else "MEDIUM" if stats["medium"] > 0 else "LOW"
            
            summary_text = f"""
            During the security assessment, <b>{stats['total']}</b> vulnerabilities were discovered,
            including <b>{stats['critical']}</b> critical and <b>{stats['high']}</b> high severity issues.
            
            The overall risk level is assessed as <b>{risk_level}</b>.
            
            It is recommended to immediately address critical and high severity vulnerabilities
            to prevent potential security incidents.
            """
            story.append(Paragraph(summary_text, self._styles['CustomBody']))
        
        # Risk Assessment
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("Risk Assessment", self._styles['VulnTitle']))
        
        if ai_summary and "risk_assessment" in ai_summary:
            text = transliterate(ai_summary["risk_assessment"])
            story.append(Paragraph(text, self._styles['CustomBody']))
        else:
            risk_text = """
            The discovered vulnerabilities may lead to:
            - Unauthorized access to confidential data
            - Compromise of user accounts
            - Financial losses and reputational damage
            - Regulatory compliance violations (GDPR, PCI-DSS)
            """
            story.append(Paragraph(risk_text, self._styles['CustomBody']))
        
        # Security Score
        if ai_summary and "overall_score" in ai_summary:
            score = ai_summary["overall_score"]
            story.append(Spacer(1, 0.5*cm))
            story.append(Paragraph(
                f"<b>Security Score: {score}/10</b>",
                self._styles['VulnTitle']
            ))
        
        return story

    def _create_charts_section(self, stats: dict) -> list:
        """Создаёт секцию с графиками."""
        story = []
        
        story.append(Paragraph("VULNERABILITY DISTRIBUTION", self._styles['SectionTitle']))
        
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
        """Создаёт pie chart распределения по severity."""
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
            
            fig, ax = plt.subplots(figsize=(8, 6))
            
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors_list,
                autopct='%1.1f%%',
                startangle=90,
                explode=[0.02] * len(sizes),
            )
            
            ax.set_title('Vulnerability Distribution by Severity', fontsize=14, fontweight='bold')
            
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
        """Создаёт bar chart по типам уязвимостей."""
        try:
            sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]
            
            if not sorted_types:
                return None
            
            labels = [t[0][:30] for t in sorted_types]
            values = [t[1] for t in sorted_types]
            
            fig, ax = plt.subplots(figsize=(10, 6))
            
            bars = ax.barh(labels, values, color='#3B82F6')
            
            ax.set_xlabel('Count')
            ax.set_title('Top 10 Vulnerability Types', fontsize=14, fontweight='bold')
            
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
        """Создаёт секцию с детальными уязвимостями."""
        story = []
        
        story.append(Paragraph("DETAILED FINDINGS", self._styles['SectionTitle']))
        
        # Сортируем по severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        sorted_vulns = sorted(
            vulns,
            key=lambda v: severity_order.get((v.severity or "informational").lower(), 5)
        )
        
        for i, vuln in enumerate(sorted_vulns[:30], 1):
            severity = (vuln.severity or "informational").lower()
            severity_color = SEVERITY_COLORS.get(severity, "#6B7280")
            severity_label = SEVERITY_LABELS_RU.get(severity, severity.upper())
            
            # Заголовок уязвимости
            story.append(Paragraph(
                f"{i}. [{severity_label.upper()}] {transliterate(vuln.vulnerability_type or 'Unknown')}",
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
                desc = transliterate(vuln.description[:500])
                story.append(Paragraph(
                    f"<b>Description:</b> {desc}",
                    self._styles['CustomBody']
                ))
            
            # Evidence
            if vuln.evidence:
                evidence = transliterate(vuln.evidence[:300])
                story.append(Paragraph(
                    f"<b>Evidence:</b> {evidence}",
                    self._styles['CustomBody']
                ))
            
            # Remediation
            if vuln.remediation:
                remediation = transliterate(vuln.remediation[:300])
                story.append(Paragraph(
                    f"<b>Remediation:</b> {remediation}",
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
        
        story.append(Paragraph("RECOMMENDATIONS", self._styles['SectionTitle']))
        
        if ai_summary and "priority_actions" in ai_summary:
            story.append(Paragraph(
                "<b>Priority Actions:</b>",
                self._styles['VulnTitle']
            ))
            
            actions = ai_summary["priority_actions"]
            if isinstance(actions, list):
                for i, action in enumerate(actions, 1):
                    text = transliterate(str(action))
                    story.append(Paragraph(
                        f"{i}. {text}",
                        self._styles['CustomBody']
                    ))
        else:
            recommendations = [
                "Immediately fix all critical vulnerabilities",
                "Conduct web server configuration audit",
                "Update all components to latest versions",
                "Implement WAF (Web Application Firewall)",
                "Set up security monitoring",
                "Train developers on secure coding practices",
                "Conduct regular penetration testing",
            ]
            
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(
                    f"{i}. {rec}",
                    self._styles['CustomBody']
                ))
        
        story.append(Spacer(1, 1*cm))
        
        # Заключение
        story.append(Paragraph("CONCLUSION", self._styles['SectionTitle']))
        story.append(Paragraph(
            """
            This report contains the results of automated security testing.
            For a complete security assessment, additional manual penetration
            testing is recommended.
            
            For questions about the test results, please contact the
            information security specialists.
            """,
            self._styles['CustomBody']
        ))
        
        return story

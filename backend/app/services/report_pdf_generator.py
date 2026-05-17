"""Генератор PDF из редактируемого отчёта ScanReport.

Создаёт профессиональный PDF-документ на основе отредактированного контента.
"""

import logging
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from app.models.database import ScanReport

logger = logging.getLogger(__name__)

# Регистрация шрифта для кириллицы
_font_registered = False


def _register_fonts():
    global _font_registered
    if _font_registered:
        return
    
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ]
    
    for path in font_paths:
        try:
            pdfmetrics.registerFont(TTFont("CyrFont", path))
            _font_registered = True
            return
        except Exception:
            continue
    
    _font_registered = True  # Fallback to default


def generate_report_pdf(report: ScanReport) -> bytes:
    """Генерирует PDF из ScanReport."""
    _register_fonts()
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    
    # Стили
    styles = getSampleStyleSheet()
    font_name = "CyrFont" if _font_registered else "Helvetica"
    
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName=font_name,
        fontSize=22,
        spaceAfter=20,
        textColor=colors.HexColor("#1a1a2e"),
    )
    
    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading1"],
        fontName=font_name,
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor("#e11d48"),
    )
    
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName=font_name,
        fontSize=11,
        leading=16,
        spaceAfter=8,
        textColor=colors.HexColor("#333333"),
    )
    
    meta_style = ParagraphStyle(
        "ReportMeta",
        parent=styles["Normal"],
        fontName=font_name,
        fontSize=10,
        textColor=colors.HexColor("#666666"),
    )
    
    story = []
    
    # Заголовок
    story.append(Paragraph(report.title or "Отчёт о тестировании безопасности", title_style))
    story.append(Spacer(1, 0.5 * cm))
    
    # Мета-информация
    if report.target_url:
        story.append(Paragraph(f"<b>Цель:</b> {report.target_url}", meta_style))
    if report.category:
        story.append(Paragraph(f"<b>Отрасль:</b> {report.category}", meta_style))
    if report.created_at:
        story.append(Paragraph(f"<b>Дата:</b> {report.created_at.strftime('%d.%m.%Y')}", meta_style))
    
    story.append(Spacer(1, 1 * cm))
    
    # Секции отчёта
    sections = [
        ("Резюме для руководства", report.executive_summary),
        ("Обнаруженные уязвимости", report.findings_summary),
        ("Оценка рисков", report.risk_assessment),
        ("Соответствие требованиям", report.compliance_notes),
        ("Рекомендации", report.recommendations),
        ("Заключение", report.conclusion),
    ]
    
    for title, content in sections:
        if content and content.strip():
            story.append(Paragraph(title, heading_style))
            # Разбиваем по абзацам
            for paragraph in content.split("\n"):
                paragraph = paragraph.strip()
                if paragraph:
                    # Экранируем HTML-символы
                    paragraph = paragraph.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    story.append(Paragraph(paragraph, body_style))
            story.append(Spacer(1, 0.5 * cm))
    
    # Генерация
    doc.build(story)
    return buffer.getvalue()

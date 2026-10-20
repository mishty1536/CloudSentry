"""Readable, in-memory PDF report generation for CloudSentry."""

import html
import io

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle


def _paragraph(value, style):
    text = "" if _is_missing(value) else str(value)
    return Paragraph(html.escape(text).replace("\n", "<br/>"), style)


def _is_missing(value):
    if value is None:
        return True
    try:
        result = pd.isna(value)
    except (TypeError, ValueError):
        return False
    return not hasattr(result, "__len__") and bool(result)


def generate_pdf_report(title, df, subtitle=None, landscape_mode=True, notes=None):
    """Generate a paginated A4 PDF, preserving all finding and metadata fields."""
    buffer = io.BytesIO()
    pagesize = landscape(A4) if landscape_mode else A4
    margin = 30
    doc = SimpleDocTemplate(
        buffer,
        pagesize=pagesize,
        rightMargin=margin,
        leftMargin=margin,
        topMargin=margin,
        bottomMargin=margin + 15,
        allowSplitting=1,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Heading1"], fontName="Helvetica-Bold",
        fontSize=16, leading=20, textColor=colors.HexColor("#0E1728"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=9, leading=12, textColor=colors.HexColor("#64748B"),
    )
    section_style = ParagraphStyle(
        "ReportSection", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, spaceBefore=8, spaceAfter=5,
        textColor=colors.HexColor("#1B3150"),
    )
    header_style = ParagraphStyle(
        "ReportHeaderCell", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=8, leading=9.5, textColor=colors.white, wordWrap="CJK",
    )
    body_style = ParagraphStyle(
        "ReportBodyCell", parent=styles["Normal"], fontName="Helvetica",
        fontSize=7.5, leading=9.2, textColor=colors.HexColor("#1E293B"),
        wordWrap="CJK",
    )
    note_style = ParagraphStyle(
        "ReportNote", parent=subtitle_style, fontSize=8, leading=11,
        wordWrap="CJK",
    )

    story = [
        Paragraph(html.escape(str(title)), title_style),
        Spacer(1, 4),
    ]
    meta_parts = [str(subtitle)] if subtitle else []
    meta_parts.append(f"Generated: {pd.Timestamp.now(tz='UTC').strftime('%Y-%m-%d %H:%M:%S UTC')}")
    story.extend((Paragraph(html.escape(" | ".join(meta_parts)), subtitle_style), Spacer(1, 8)))

    if notes:
        story.append(Paragraph("Assessment and coverage", section_style))
        for note in notes:
            story.append(Paragraph(html.escape(str(note)), note_style))
        story.append(Spacer(1, 7))

    if df is None or df.empty:
        story.append(Paragraph("No records found.", body_style))
    else:
        columns = [str(column) for column in df.columns]
        lower_to_column = {column.lower(): column for column in columns}
        primary_keys = ("service", "severity", "finding", "recommendation")
        primary_columns = [lower_to_column[key] for key in primary_keys if key in lower_to_column]
        metadata_columns = [column for column in columns if column not in primary_columns]
        usable_width = pagesize[0] - 2 * margin

        if primary_columns:
            story.append(Paragraph("Findings", section_style))
            header = [_paragraph("#", header_style)]
            header.extend(_paragraph(column.replace("_", " ").title(), header_style)
                          for column in primary_columns)
            main_data = [header]
            for row_number, (_, row) in enumerate(df.iterrows(), start=1):
                main_data.append([_paragraph(row_number, body_style)] + [
                    _paragraph(row[column], body_style) for column in primary_columns
                ])

            if len(primary_columns) == 4:
                widths = [24, 68, 58, 270, usable_width - 420]
            else:
                widths = [24] + [max(55, (usable_width - 24) / len(primary_columns))] * len(primary_columns)
                widths[-1] += usable_width - sum(widths)
            main_table = LongTable(
                main_data, colWidths=widths, repeatRows=1, splitByRow=1, splitInRow=1
            )
            main_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B3150")),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#F8FAFC")]),
            ]))
            story.append(main_table)

        if metadata_columns:
            if not primary_columns:
                generic_data = [[
                    _paragraph(column.replace("_", " ").title(), header_style)
                    for column in columns
                ]]
                generic_data.extend([
                    [_paragraph(row[column], body_style) for column in columns]
                    for _, row in df.iterrows()
                ])
                generic_widths = [usable_width / len(columns)] * len(columns)
                generic_widths[-1] += usable_width - sum(generic_widths)
                generic_table = LongTable(
                    generic_data,
                    colWidths=generic_widths,
                    repeatRows=1,
                    splitByRow=1,
                    splitInRow=1,
                )
                generic_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B3150")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.white, colors.HexColor("#F8FAFC")]),
                ]))
                story.append(generic_table)
                metadata_columns = []

        if metadata_columns:
            story.append(Paragraph("Resource, policy, and other finding details", section_style))
            detail_data = [[
                _paragraph("Finding #", header_style),
                _paragraph("Field", header_style),
                _paragraph("Value", header_style),
            ]]
            for row_number, (_, row) in enumerate(df.iterrows(), start=1):
                for column in metadata_columns:
                    value = row[column]
                    if _is_missing(value) or not str(value).strip():
                        continue
                    detail_data.append([
                        _paragraph(row_number, body_style),
                        _paragraph(column.replace("_", " ").title(), body_style),
                        _paragraph(value, body_style),
                    ])
            if len(detail_data) > 1:
                details_table = LongTable(
                    detail_data,
                    colWidths=[55, 125, usable_width - 180],
                    repeatRows=1,
                    splitByRow=1,
                    splitInRow=1,
                )
                details_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B3150")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.white, colors.HexColor("#F8FAFC")]),
                ]))
                story.append(details_table)

    def draw_page(canvas, doc_obj):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(margin, 15, "CloudSentry | Cloud Security Misconfiguration Auditor")
        canvas.drawRightString(pagesize[0] - margin, 15, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return buffer.getvalue()

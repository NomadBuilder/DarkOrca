"""Branded PDF report generation for DarkOrca audits."""

from __future__ import annotations

import io
from datetime import datetime
from typing import List, Optional

from ..models.scan import ScanResult
from ..models.finding import Finding, FindingSeverity
from ..utils.executive_summary import build_executive_summary
from ..utils.finding_confidence import classify_finding_confidence, confidence_label


class PDFReporter:
    @staticmethod
    def is_available() -> bool:
        try:
            import reportlab  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def generate(result: ScanResult) -> io.BytesIO:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
        styles = getSampleStyleSheet()
        story: List = []

        accent = colors.HexColor("#ff6b6b")
        muted = colors.HexColor("#6b7280")
        dark = colors.HexColor("#111827")

        title_style = ParagraphStyle(
            "Title", parent=styles["Heading1"], fontSize=22, textColor=dark, spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "Subtitle", parent=styles["Normal"], fontSize=11, textColor=muted, spaceAfter=14,
        )
        h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, textColor=dark, spaceBefore=12, spaceAfter=6)
        body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=8)
        small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=9, textColor=muted)

        result_dict = result.to_dict()
        result_dict["scan_preset_label"] = result.metadata.get("scan_preset_label") if result.metadata else None
        summary = build_executive_summary(result_dict)
        target_url = result.target.url if result.target else "Unknown"
        completed = result.scan_completed_at or datetime.utcnow()

        story.append(Paragraph("Dark AI · DarkOrca", subtitle_style))
        story.append(Paragraph("Security Audit Report", title_style))
        story.append(Paragraph(f"Target: {target_url}", body))
        story.append(Paragraph(f"Completed: {completed.strftime('%Y-%m-%d %H:%M UTC')}", small))
        story.append(Spacer(1, 0.15 * inch))

        metrics = [
            ["Risk Score", f"{summary['risk_score']:.1f} / 100"],
            ["Risk Level", summary["risk_level"]],
            ["Actionable Findings", str(summary["actionable_count"])],
            ["Confirmed Issues", str(summary["confirmed_count"])],
        ]
        table = Table(metrics, colWidths=[2.2 * inch, 3.5 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR", (0, 0), (-1, -1), dark),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Executive Summary", h2))
        story.append(Paragraph(summary["overview"], body))
        story.append(Paragraph(f"<b>Recommended next step:</b> {summary['recommendation']}", body))

        if summary["top_priorities"]:
            story.append(Paragraph("Top Priorities", h2))
            for idx, item in enumerate(summary["top_priorities"], 1):
                story.append(Paragraph(
                    f"{idx}. <b>{item['title']}</b> "
                    f"({item['severity']}, {item['confidence']})<br/>{item.get('remediation') or ''}",
                    body,
                ))

        actionable = PDFReporter._actionable_findings(result.findings)
        if actionable:
            story.append(Paragraph("Detailed Findings", h2))
            for finding in actionable[:40]:
                conf = confidence_label(classify_finding_confidence(finding.to_dict()))
                story.append(Paragraph(
                    f"<b>{finding.title}</b> — {finding.severity.value.title()} ({conf})",
                    body,
                ))
                if finding.description:
                    story.append(Paragraph(finding.description[:600], small))
                if finding.remediation:
                    story.append(Paragraph(f"<i>Remediation:</i> {finding.remediation[:400]}", small))
                story.append(Spacer(1, 0.08 * inch))

        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(
            "Prepared by Dark AI — DarkOrca Managed Security Audits. "
            "This report is intended for authorized recipients only.",
            small,
        ))

        doc.build(story)
        buffer.seek(0)
        return buffer

    @staticmethod
    def _actionable_findings(findings: List[Finding]) -> List[Finding]:
        order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        filtered = []
        for finding in findings:
            title = finding.title.lower()
            if finding.severity == FindingSeverity.INFO and finding.category.value == "fingerprinting":
                continue
            if "plugin detected" in title or "theme detected" in title:
                continue
            filtered.append(finding)
        return sorted(filtered, key=lambda f: order.get(f.severity, 99))

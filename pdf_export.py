from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4


def generate_executive_pdf(summary: dict, path: str) -> None:
    """
    Create a simple executive PDF report summarizing key cyber risk metrics.

    summary keys expected:
        - scan_type
        - hosts
        - vulns
        - risk_level
        - threat_score
    """
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4)
    story = []

    story.append(
        Paragraph("Cyber Risk Assessment – Executive Summary", styles["Title"])
    )
    story.append(Spacer(1, 18))

    story.append(
        Paragraph(f"Scan Type: {summary.get('scan_type', 'N/A')}", styles["Normal"])
    )
    story.append(
        Paragraph(f"Total Hosts: {summary.get('hosts', 'N/A')}", styles["Normal"])
    )
    story.append(
        Paragraph(
            f"Total Vulnerabilities: {summary.get('vulns', 'N/A')}", styles["Normal"]
        )
    )
    story.append(
        Paragraph(f"Risk Level: {summary.get('risk_level', 'N/A')}", styles["Normal"])
    )
    story.append(
        Paragraph(
            f"Threat Score: {summary.get('threat_score', 'N/A')}", styles["Normal"]
        )
    )

    doc.build(story)

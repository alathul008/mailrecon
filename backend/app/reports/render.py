from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet


def _pdf_text(value) -> str:
    return escape("" if value is None else str(value))


def pdf_report(inv, findings, factors):
    buf=BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36); styles=getSampleStyleSheet(); story=[]
    story += [Paragraph("MailRecon — Email OSINT Investigation",styles["Title"]),Spacer(1,10),Paragraph(f"Target: {_pdf_text(inv.target)}",styles["Normal"]),Paragraph(f"Investigated: {_pdf_text(inv.created_at)}",styles["Normal"]),Paragraph(f"Risk: {_pdf_text(inv.risk_score)}/100 — {_pdf_text(inv.risk_level)}",styles["Heading2"]),Spacer(1,10)]
    story.append(Paragraph("Executive summary",styles["Heading2"])); story.append(Paragraph("OSINT findings are probabilistic and should be independently verified. This report contains only evidence collected by configured public/legitimate providers and local analysis.",styles["BodyText"])); story.append(Spacer(1,10))
    story.append(Paragraph("Risk factors",styles["Heading2"])); data=[["Delta","Reason"]]+[[_pdf_text(f.get("delta")),_pdf_text(f.get("reason"))] for f in factors]; t=Table(data,colWidths=[60,420]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.3,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey)])); story.append(t); story.append(Spacer(1,10))
    story.append(Paragraph("Findings",styles["Heading2"])); rows=[["Source","Type","Value","Confidence","Severity"]]
    for f in findings: rows.append([_pdf_text(f.source),_pdf_text(f.finding_type),_pdf_text(f.value)[:80],_pdf_text(f"{f.confidence:.0%}"),_pdf_text(f.severity)])
    t=Table(rows,colWidths=[90,85,200,65,65],repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(t)
    doc.build(story); buf.seek(0); return buf

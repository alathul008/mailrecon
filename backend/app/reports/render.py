from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

def pdf_report(inv, findings, factors):
    buf=BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36); styles=getSampleStyleSheet(); story=[]
    story += [Paragraph("MailRecon — Email OSINT Investigation",styles["Title"]),Spacer(1,10),Paragraph(f"Target: {inv.target}",styles["Normal"]),Paragraph(f"Investigated: {inv.created_at}",styles["Normal"]),Paragraph(f"Risk: {inv.risk_score}/100 — {inv.risk_level}",styles["Heading2"]),Spacer(1,10)]
    story.append(Paragraph("Executive summary",styles["Heading2"])); story.append(Paragraph("OSINT findings are probabilistic and should be independently verified. This report contains only evidence collected by configured public/legitimate providers and local analysis.",styles["BodyText"])); story.append(Spacer(1,10))
    story.append(Paragraph("Risk factors",styles["Heading2"])); data=[["Delta","Reason"]]+[[str(f.get("delta")),f.get("reason")] for f in factors]; t=Table(data,colWidths=[60,420]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.3,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey)])); story.append(t); story.append(Spacer(1,10))
    story.append(Paragraph("Findings",styles["Heading2"])); rows=[["Source","Type","Value","Confidence","Severity"]]
    for f in findings: rows.append([f.source,f.finding_type,f.value[:80],f"{f.confidence:.0%}",f.severity])
    t=Table(rows,colWidths=[90,85,200,65,65],repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(t)
    doc.build(story); buf.seek(0); return buf

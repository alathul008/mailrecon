from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from app.osint.correlation import correlate_email_findings


def _pdf_text(value) -> str:
    return escape("" if value is None else str(value))


def pdf_report(inv, findings, factors, provenance=None):
    provenance = provenance or {}
    buf=BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36); styles=getSampleStyleSheet(); story=[]
    story += [Paragraph("MailRecon — Email OSINT Investigation",styles["Title"]),Spacer(1,10),Paragraph(f"Target: {_pdf_text(inv.target)}",styles["Normal"]),Paragraph(f"Investigated: {_pdf_text(inv.created_at)}",styles["Normal"]),Paragraph(f"Risk: {_pdf_text(inv.risk_score)}/100 — {_pdf_text(inv.risk_level)}",styles["Heading2"]),Spacer(1,10)]
    story.append(Paragraph("Provenance",styles["Heading2"]))
    provenance_rows=[["Field","Value"]]+[[_pdf_text(key),_pdf_text(value)] for key,value in provenance.items()]
    provenance_table=Table(provenance_rows,colWidths=[180,300],repeatRows=1); provenance_table.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(provenance_table); story.append(Spacer(1,10))
    story.append(Paragraph("Executive summary",styles["Heading2"])); story.append(Paragraph("OSINT findings are probabilistic and should be independently verified. This report contains only evidence collected by configured public/legitimate providers and local analysis.",styles["BodyText"])); story.append(Spacer(1,10))
    story.append(Paragraph("Correlation assessment",styles["Heading2"]))
    projection=[{"id":getattr(f,"id",None),"source":getattr(f,"source",None),"finding_type":getattr(f,"finding_type",None),"value":getattr(f,"value",None),"confidence":getattr(f,"confidence",0),"evidence_state":getattr(f,"evidence_state",None),"notes":getattr(f,"notes",None),"raw_reference":getattr(f,"raw_reference",None)} for f in findings]
    correlation=correlate_email_findings(projection)
    story.append(Paragraph("Derived relationships are hypotheses; correlated relationships explain linked observations and do not confirm human identity.",styles["BodyText"]))
    corr_rows=[["Relationship","State","Confidence","Support"]]
    for rel in correlation.get("relationships",[]):
        corr_rows.append([_pdf_text(f"{rel['source']} → {rel['target']} ({rel['relationship']})")[:90],_pdf_text(rel["evidence_state"]),_pdf_text(f"{rel['confidence']:.0%}"),_pdf_text(", ".join(map(str,rel["supporting_finding_ids"])) or "none")])
    if len(corr_rows)==1:corr_rows.append(["No cross-signal relationships observed","—","—","—"])
    corr_table=Table(corr_rows,colWidths=[300,75,65,60],repeatRows=1); corr_table.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(corr_table)
    if correlation.get("conflicts"):
        story.append(Spacer(1,6));story.append(Paragraph("Provider conflicts are preserved rather than arbitrarily resolved.",styles["BodyText"]))
    story.append(Spacer(1,10))
    story.append(Paragraph("Risk factors",styles["Heading2"])); data=[["Delta","Reason"]]+[[_pdf_text(f.get("delta")),_pdf_text(f.get("reason"))] for f in factors]; t=Table(data,colWidths=[60,420]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.3,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey)])); story.append(t); story.append(Spacer(1,10))
    story.append(Paragraph("Findings",styles["Heading2"])); rows=[["Source","Type","Value","Confidence","Severity","Evidence","Attempt"]]
    current_attempt=provenance.get("execution_attempt_id")
    for f in findings:
        attempt_id=getattr(f,"execution_attempt_id",None)
        if current_attempt and attempt_id == current_attempt: attempt_label="current"
        elif current_attempt and attempt_id: attempt_label="historical"
        else: attempt_label="unspecified"
        evidence=getattr(f,"evidence_state",None)
        if not evidence:
            notes=getattr(f,"notes",None) or ""; marker="Evidence state: "
            evidence=notes.split(marker,1)[1].split(".",1)[0].strip() if marker in notes else None
        rows.append([_pdf_text(getattr(f,"source",None)),_pdf_text(getattr(f,"finding_type",None)),_pdf_text(getattr(f,"value",None))[:70],_pdf_text(f"{getattr(f,'confidence',0):.0%}"),_pdf_text(getattr(f,"severity",None)),_pdf_text(evidence),_pdf_text(attempt_label)])
    t=Table(rows,colWidths=[70,65,130,55,55,65,60],repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(t)
    doc.build(story); buf.seek(0); return buf

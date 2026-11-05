import io
import json
from html import escape

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from .analysis import now


def sections(record, settings):
    a = record["analysis"]
    p = a["parsed"]
    risk = a["risk"]
    finding_text = [
        f"{f['id']}: {f['title']}. Evidence: {f['evidence']}. Interpretation: {f['reason']}"
        for f in a["findings"]
    ]
    return [
        (
            "Executive Summary",
            [
                f"{record['name']}: {risk['severity'].upper()}, score {risk['score']}/100. {len(a['findings'])} local findings and {len(a['iocs'])} indicators. {risk['compromise']}.",
                "SIMULATION: synthetic reserved-domain evidence."
                if record["simulation"]
                else "Submitted email evidence. Intent is not independently confirmed.",
            ],
        ),
        (
            "Incident Identification",
            [
                f"ID: {record['id']}",
                f"Created: {record['created_at']}",
                f"Analysis revision: {record['revision_id']}",
                f"Analyst: {settings['analyst_name']}",
                f"Organization: {settings['organization']}",
            ],
        ),
        (
            "Incident Description",
            [f"Subject: {p['subject']}", p["plain_text"] or p["html_text"]],
        ),
        (
            "Investigation Scope",
            [
                "Static examination of supplied email bytes, headers, MIME parts and text. External lookups are opt-in and recorded separately. Endpoint, mailbox and identity telemetry are outside scope."
            ],
        ),
        (
            "Email Metadata",
            [
                ["Field", "Value"],
                *[
                    [k, p[k]]
                    for k in [
                        "sender",
                        "recipient",
                        "reply_to",
                        "subject",
                        "date",
                        "message_id",
                    ]
                ],
            ],
        ),
        (
            "Email Header Analysis",
            [["Header", "Value"], *[[h["name"], h["value"]] for h in p["headers"]]],
        ),
        (
            "Authentication Analysis",
            [
                ["Method", "Result", "Evidence trust"],
                *[
                    [k.upper(), v["result"], v["trust"]]
                    for k, v in p["authentication"].items()
                ],
            ],
        ),
        (
            "Technical Findings",
            finding_text
            or [
                "No configured local risk factors were detected. This is not a guarantee of safety."
            ],
        ),
        (
            "Indicators of Compromise",
            [
                ["Type", "Indicator", "Source / reason"],
                *[
                    [i["type"], i["value"], i["source"] + ": " + i["reason"]]
                    for i in a["iocs"]
                ],
            ],
        ),
        (
            "Threat Intelligence Results",
            [json.dumps(i, ensure_ascii=False) for i in record["intelligence"]]
            or [
                "No external intelligence lookup has been completed. Local heuristic assessment — not externally verified."
            ],
        ),
        (
            "MITRE ATT&CK Mapping",
            [
                f"{m['id']} {m['name']} / {m['tactic']} / {m['state']} / confidence {m['confidence']}. Evidence: {json.dumps(m['evidence'])}. {m['justification']} Source: {m['url']}"
                for m in a["mappings"]
            ]
            or ["No evidence-supported mapping."],
        ),
        (
            "Risk and Severity Assessment",
            [
                f"Score: {risk['score']}/100; severity: {risk['severity']}; confidence: {risk['confidence']}.",
                risk["reasoning"],
                *[
                    f"{f['title']}: +{f['points']}. {f['reason']} Evidence: {f['evidence']}"
                    for f in risk["factors"]
                ],
            ],
        ),
        (
            "Evidence Register",
            [
                f"E001: Original email, SHA-256 {record['evidence_sha256']}; preserved exact bytes.",
                *[
                    f"E{n + 2:03}: {att['filename']}; MIME {att['content_type']}; {att['size']} bytes; SHA-256 {att['sha256']}"
                    for n, att in enumerate(p["attachments"])
                ],
            ],
            ["Analyst notes: " + (record["notes"] or "None recorded.")],
        ),
        (
            "Incident Response Recommendations",
            [
                f"{r['phase']}: {r['action']} {r['reason']} Finding references: {', '.join(r['evidence']) or 'none'}"
                for r in a["recommendations"]
            ],
        ),
        (
            "Investigation Timeline",
            [
                f"{record['created_at']}: Evidence submitted.",
                *[
                    f"{r['created_at']}: Local analysis revision {r['id']}."
                    for r in record["revisions"]
                ],
                *[
                    f"{i['checked_at']}: Explicit {i['provider']} lookup: {i['status']}."
                    for i in record["intelligence"]
                ],
                *[
                    f"{e['created_at']}: {e['format']} report exported (revision {e['revision_id']})."
                    for e in record["exports"]
                ],
                f"{now()}: Report prepared.",
            ],
        ),
        ("Limitations and Unverified Findings", a["limitations"]),
        (
            "Conclusion",
            [
                f"{risk['severity'].title()} local email risk assessment. {risk['compromise']}. Validate suspicious indicators before blocking infrastructure or applying account remediation."
            ],
        ),
        (
            "References",
            [
                "MITRE Enterprise ATT&CK: https://attack.mitre.org/",
                *sorted(set(m["url"] for m in a["mappings"])),
                "PhishScope local rule engine 1.0.0. Thresholds are application-defined; this report is not a breach determination.",
            ],
        ),
    ]


def iter_items(section):
    for block in section[1:]:
        yield from block


def markdown(record, settings):
    lines = [
        "# PhishScope — Incident Investigation Report",
        f"Classification: {settings['classification']}",
        f"Generated: {now()}",
        "",
    ]
    for section in sections(record, settings):
        lines.append("## " + section[0])
        for index, item in enumerate(iter_items(section)):
            if isinstance(item, list):
                lines.append(
                    "| "
                    + " | ".join(
                        escape(str(x)).replace("\n", " ").replace("|", "\\|")
                        for x in item
                    )
                    + " |"
                )
                if index == 0:
                    lines.append("| " + " | ".join("---" for _ in item) + " |")
            else:
                lines.append(escape(str(item)))
                lines.append("")
        lines.append("")
    return "\n".join(lines)


def pdf(record, settings):
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "SmallCell",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            wordWrap="CJK",
        )
    )
    styles["BodyText"].wordWrap = "CJK"

    def para(value, style="BodyText"):
        # ReportLab markup must never interpret attacker-supplied email strings.
        punctuation = str.maketrans(
            {
                "—": " - ",
                "–": "-",
                "’": "'",
                "“": '"',
                "”": '"',
                "→": " -> ",
                "…": "...",
            }
        )
        clean = str(value).translate(punctuation).encode("ascii", "replace").decode()
        return Paragraph(escape(clean).replace("\n", "<br/>"), styles[style])

    doc = SimpleDocTemplate(
        output,
        pagesize=(595.27, 841.89),
        rightMargin=40,
        leftMargin=40,
        topMargin=46,
        bottomMargin=46,
        title="PhishScope Incident Investigation Report",
        author=settings["analyst_name"],
    )
    story = [
        Spacer(1, inch),
        para("PHISHSCOPE", "Title"),
        Spacer(1, 20),
        para("Incident Investigation Report", "Heading1"),
        para(record["name"], "Heading2"),
        para(record["id"]),
        Spacer(1, 20),
        para(
            f"{record['analysis']['risk']['severity'].upper()} / {record['analysis']['risk']['score']} of 100"
        ),
        para(
            "SIMULATION — Synthetic email evidence"
            if record["simulation"]
            else "Email evidence investigation"
        ),
        para(f"Classification: {settings['classification']}"),
        para(f"Analyst: {settings['analyst_name']}"),
        para(f"Generated: {now()}"),
        PageBreak(),
    ]
    for section in sections(record, settings):
        story.append(para(section[0], "Heading2"))
        items = list(iter_items(section))
        if items and isinstance(items[0], list):
            rows = [[para(c, "SmallCell") for c in row] for row in items]
            table = Table(
                rows,
                colWidths=[515.27 / len(items[0])] * len(items[0]),
                repeatRows=1,
                splitInRow=1,
                hAlign="LEFT",
            )
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef5")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ]
                )
            )
            story.append(table)
        else:
            for item in items:
                story.extend([para(item), Spacer(1, 6)])
        story.append(Spacer(1, 10))

    def footer(canvas, _):
        canvas.setFont("Helvetica", 8)
        canvas.drawString(40, 24, settings["classification"] + " | PhishScope")
        canvas.drawRightString(555, 24, f"Page {doc.page}")

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()

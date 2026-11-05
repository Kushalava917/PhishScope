"""Create a one-page comparison from the two saved investigation revisions."""

import json
from collections import Counter
from html import escape
from pathlib import Path

from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "phishscope-investigation-comparison.pdf"
IDS = ["e9610c39-c254-4000-8964-7a4626f0e21f", "08e08a59-f0db-4c44-b354-a4ef885f6168"]
NAVY = colors.HexColor("#15263d")
INK = colors.HexColor("#23364f")
MUTED = colors.HexColor("#566a82")
RULE = colors.HexColor("#d8e1eb")
RED = colors.HexColor("#ac3447")
GREEN = colors.HexColor("#24725b")


def load_records():
    records = json.loads(
        (ROOT / "docs/samples/comparison-investigations.json").read_text(
            encoding="utf-8"
        )
    )
    if [record["id"] for record in records] != IDS or not all(
        record.get("simulation") is True for record in records
    ):
        raise ValueError(
            "Expected the two checked-in synthetic investigation snapshots"
        )
    return records


def style(name, size=9, leading=12, color=INK, **kwargs):
    return ParagraphStyle(
        name,
        fontName=kwargs.pop("fontName", "Helvetica"),
        fontSize=size,
        leading=leading,
        textColor=color,
        alignment=TA_LEFT,
        **kwargs,
    )


BODY = style("Body")
LABEL = style("Label", 8.5, 11, MUTED, fontName="Helvetica-Bold")
SMALL = style("Small", 8, 10.5, MUTED)


def p(text, custom=BODY):
    return Paragraph(text, custom)


def literal(text):
    return escape(str(text))


def main():
    phishing, benign = load_records()
    pa, ba = phishing["analysis"], benign["analysis"]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    story = [
        p(
            "PHISHSCOPE  /  INVESTIGATION COMPARISON",
            style("Eyebrow", 8, 11, MUTED, fontName="Helvetica-Bold", spaceAfter=8),
        ),
        p(
            "Phishing vs. legitimate email",
            style("Title", 25, 29, NAVY, fontName="Helvetica-Bold", spaceAfter=7),
        ),
        p("Synthetic case comparison | 05 November 2026 | CONFIDENTIAL", SMALL),
        Spacer(1, 17),
    ]
    cards = []
    for record, color in [(phishing, RED), (benign, GREEN)]:
        a = record["analysis"]
        cards.append(
            [
                p(
                    literal(record["name"]),
                    style("Case", 10, 13, color, fontName="Helvetica-Bold"),
                ),
                Spacer(1, 5),
                p(
                    f'<b>{a["risk"]["score"]}</b><font size="12"> /100</font>  <font size="10">{a["risk"]["severity"].upper()}</font>',
                    style("Score", 26, 31, color),
                ),
                p(
                    f"{len(a['findings'])} risk findings | {len(a['iocs'])} extracted indicators",
                    SMALL,
                ),
            ]
        )
    scorecards = Table([cards], colWidths=[261.5, 261.5])
    scorecards.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#fcf0f2")),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#eef7f2")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (-1, -1), 11),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
                ("LINEAFTER", (0, 0), (0, 0), 5, colors.white),
            ]
        )
    )
    story.extend([scorecards, Spacer(1, 17)])

    def cell(value):
        return p(value)

    def row(label, left, right):
        return [p(literal(label), LABEL), cell(left), cell(right)]

    observed = {f["code"] for f in pa["findings"]}
    assert {
        "reply_mismatch",
        "brand_impersonation",
        "urgency",
        "credential_lure",
        "link_mismatch",
        "hidden_link",
        "redirect_metadata",
    } <= observed
    assert not ba["findings"]
    rows = [
        [
            p(
                "COMPARE",
                style("HeaderLabel", 8, 11, colors.white, fontName="Helvetica-Bold"),
            ),
            p(
                "PHISHING SIMULATION",
                style("HeaderLeft", 8, 11, colors.white, fontName="Helvetica-Bold"),
            ),
            p(
                "LEGITIMATE CONTROL",
                style("HeaderRight", 8, 11, colors.white, fontName="Helvetica-Bold"),
            ),
        ]
    ]
    rows.append(
        row(
            "Message context",
            'Claims "Microsoft Security" from<br/><b>verify-account.example</b>.<br/>Urgent account-verification request.',
            "Taylor Morgan at <b>company.example</b>.<br/>Routine project-planning meeting.",
        )
    )
    rows.append(
        row(
            "Key findings",
            "<b>F001-F002:</b> Different Reply-To domain; brand impersonation indicator.<br/>"
            "<b>F006-F007:</b> Urgency and credential request.<br/>"
            "<b>F008-F010:</b> Disguised destination, hidden link, and embedded redirect target.",
            "No configured local risk factors detected.<br/><br/>No Reply-To supplied; no credential lure, urgency trigger, URL, or attachment detected.",
        )
    )
    for method in ("spf", "dkim", "dmarc"):
        left = literal(pa["parsed"]["authentication"][method]["result"].upper())
        right = literal(ba["parsed"]["authentication"][method]["result"].upper())
        rows.append(
            row(
                f"{method.upper()} (reported)",
                f'<font color="#ac3447"><b>{left}</b></font>',
                f'<font color="#24725b"><b>{right}</b></font>',
            )
        )
    counts = [Counter(i["type"] for i in a["iocs"]) for a in (pa, ba)]
    rows.append(
        row(
            "Indicator footprint",
            f"{len(pa['iocs'])} extracted values, including <b>{counts[0]['url']} URLs</b>.<br/>No attachments. Reputation unverified.",
            f"{len(ba['iocs'])} extracted values; <b>{counts[1]['url']} URLs</b>.<br/>No attachments. Extraction is not a threat verdict.",
        )
    )

    def mappings(a):
        return (
            "<br/>".join(
                f"<b>{literal(m['id'])}</b> - {literal(m['name'])}"
                for m in a["mappings"]
            )
            or "No evidence-supported mappings."
        )

    rows.append(
        row(
            "ATT&CK mapping",
            mappings(pa)
            + '<br/><font color="#566a82">Initial Access; suspected; medium confidence.</font>',
            mappings(ba)
            + '<br/><font color="#566a82">Phishing and execution are not established.</font>',
        )
    )
    rows.append(
        row(
            "Assessment limits",
            f"Local assessment confidence: <b>{pa['risk']['confidence']}</b>.<br/>No evidence of successful compromise.",
            f"Local assessment confidence: <b>{ba['risk']['confidence']}</b>.<br/>A 0 score does not guarantee safety.",
        )
    )
    table = Table(rows, colWidths=[101, 211, 211], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f2f5f9")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, NAVY),
                ("LINEBELOW", (0, 1), (-1, -1), 0.5, RULE),
                ("LINEBEFORE", (1, 1), (-1, -1), 0.4, RULE),
            ]
        )
    )
    story.extend(
        [
            table,
            Spacer(1, 12),
            p(
                "<b>Interpretation:</b> Corroborating identity, social-engineering and link anomalies distinguish the phishing sample from the routine business email. Neither record establishes a click, execution, credential exposure or breach.",
                SMALL,
            ),
            Spacer(1, 7),
            p(
                "<b>Evidence caveat:</b> Authentication results are supplied-header claims; gateway provenance is unverified. No external intelligence was queried. Scores are local heuristics with application-defined thresholds, not an externally verified safety verdict.",
                SMALL,
            ),
            Spacer(1, 10),
            p(
                f"<b>Saved sources:</b> Phishing {phishing['id']}<br/>Legitimate {benign['id']} | Engine {literal(pa['engine_version'])}",
                style("Sources", 7.2, 9.5, MUTED),
            ),
        ]
    )

    def footer(canvas, doc):
        canvas.setStrokeColor(RULE)
        canvas.line(36, 30, 559, 30)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(36, 18, "CONFIDENTIAL | SIMULATION ONLY | PhishScope")
        canvas.drawRightString(559, 18, f"Page {doc.page}")

    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=(595, 842),
        leftMargin=36,
        rightMargin=36,
        topMargin=32,
        bottomMargin=40,
        title="PhishScope - Phishing vs. Legitimate Email",
        author="PhishScope SOC Workspace",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    reader = PdfReader(str(OUTPUT))
    if len(reader.pages) != 1:
        raise AssertionError(f"Expected one page; generated {len(reader.pages)}")
    text = reader.pages[0].extract_text()
    for value in [
        "100",
        "0",
        "F001-F002",
        "SPF",
        "DKIM",
        "DMARC",
        "T1566.002",
        "No evidence-supported mappings.",
        *IDS,
    ]:
        assert value in text, value
    print(f"Created and verified one page: {OUTPUT}")


if __name__ == "__main__":
    main()

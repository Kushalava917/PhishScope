from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import PurePosixPath
from urllib.parse import parse_qs, unquote, urlsplit

import tldextract
from bs4 import BeautifulSoup

from .techniques import TECHNIQUES

MAX_EMAIL = 5 * 1024 * 1024
extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}"
)


def now():
    return datetime.now(timezone.utc).isoformat()


def classify_risk(score):
    return (
        "critical"
        if score >= 75
        else "high"
        if score >= 50
        else "medium"
        if score >= 25
        else "low"
    )


def domain(address):
    return parseaddr(address)[1].rsplit("@", 1)[-1].lower() if "@" in address else ""


def base_domain(host):
    parsed = extract_domain(host)
    return parsed.top_domain_under_public_suffix or host.lower()


def safe_filename(value):
    return (
        re.sub(r"[^\w. ()-]", "_", PurePosixPath(value.replace("\\", "/")).name)[:180]
        or "unnamed"
    )


def analyze(raw: bytes):
    if len(raw) > MAX_EMAIL:
        raise ValueError("Email exceeds the 5 MiB limit")
    if b"\x00" in raw or raw.startswith((b"MZ", b"PK\x03\x04", b"%PDF", b"\x89PNG")):
        raise ValueError("Expected a textual RFC email, not a binary file")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if not msg.get("From") or not msg.get("Subject"):
        raise ValueError("Email must contain From and Subject headers")
    findings, indicators, attachments, mime, plain, html = [], {}, [], [], [], []
    timestamp = now()

    def flag(code, title, points, evidence, reason, confidence="medium"):
        findings.append(
            {
                "id": f"F{len(findings) + 1:03}",
                "code": code,
                "title": title,
                "points": points,
                "evidence": evidence[:2000],
                "reason": reason,
                "confidence": confidence,
                "state": "observed",
            }
        )

    def ioc(value, kind, source, reason="Extracted from original evidence"):
        value = value.strip().rstrip(".,;)")
        if not value or len(value) > 4096:
            return
        if kind in {"domain", "email", "md5", "sha1", "sha256"}:
            value = value.lower()
        k = (kind, value)
        evidence = {"source": source, "excerpt": value[:300]}
        if k in indicators:
            if evidence not in indicators[k]["evidence"]:
                indicators[k]["evidence"].append(evidence)
            return
        indicators[k] = {
            "id": hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:16],
            "value": value,
            "type": kind,
            "source": source,
            "reason": reason,
            "reputation": "unverified",
            "confidence": "high" if kind != "domain" else "medium",
            "first_observed": timestamp,
            "evidence": [evidence],
            "assessment": "Local heuristic assessment — not externally verified.",
        }

    parts = list(msg.walk())
    if len(parts) > 200:
        raise ValueError("Email exceeds 200 MIME parts")
    for index, part in enumerate(parts):
        mime.append(
            {
                "index": index,
                "type": part.get_content_type(),
                "disposition": part.get_content_disposition(),
                "filename": safe_filename(part.get_filename())
                if part.get_filename()
                else None,
            }
        )
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if part.get_filename() or part.get_content_disposition() == "attachment":
            filename = safe_filename(part.get_filename() or "unnamed")
            hashes = {
                "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
                "sha1": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            attachments.append(
                {
                    "filename": filename,
                    "original_filename": part.get_filename(),
                    "content_type": part.get_content_type(),
                    "size": len(payload),
                    **hashes,
                }
            )
            ioc(filename, "filename", f"MIME part {index}")
            for kind, value in hashes.items():
                ioc(
                    value,
                    kind,
                    f"Attachment {filename}",
                    "Computed from decoded attachment bytes; never executed",
                )
            if re.search(
                r"\.(exe|scr|js|vbs|bat|cmd|ps1|lnk|iso|hta|docm|xlsm)$", filename, re.I
            ):
                flag(
                    "risky_attachment",
                    "Potentially active attachment",
                    25,
                    filename,
                    "Executable, script, shortcut or macro-enabled extension; contents were not executed.",
                )
            if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.\w+$", filename, re.I):
                flag(
                    "double_extension",
                    "Double file extension",
                    15,
                    filename,
                    "A document-like extension precedes another extension, potentially disguising file type.",
                )
            expected = {
                ".pdf": "application/pdf",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".txt": "text/plain",
            }.get(PurePosixPath(filename).suffix.lower())
            if (expected and expected != part.get_content_type()) or (
                part.get_content_type() == "application/pdf"
                and not payload.startswith(b"%PDF")
            ):
                flag(
                    "mime_mismatch",
                    "Attachment MIME mismatch",
                    15,
                    f"{filename}: {part.get_content_type()}",
                    "Declared MIME type does not match extension or recognized file signature.",
                )
        elif part.get_content_type() in {"text/plain", "text/html"}:
            try:
                text = payload.decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            (html if part.get_content_type() == "text/html" else plain).append(text)
    body_plain, body_html = "\n".join(plain), "\n".join(html)
    soup = BeautifulSoup(body_html, "html.parser")
    all_text = body_plain + "\n" + soup.get_text(" ", strip=True)
    sender, reply = str(msg.get("From", "")), str(msg.get("Reply-To", ""))
    sender_domain = domain(sender)
    envelope_sender = str(msg.get("Return-Path", ""))
    if domain(envelope_sender) and base_domain(domain(envelope_sender)) != base_domain(
        sender_domain
    ):
        flag(
            "envelope_mismatch",
            "Envelope sender domain mismatch",
            8,
            f"From: {sender}; Return-Path: {envelope_sender}",
            "Envelope and visible sender domains differ. Mailing services and forwarding can legitimately cause this; verify organizational alignment.",
        )
    if reply and base_domain(domain(reply)) != base_domain(sender_domain):
        flag(
            "reply_mismatch",
            "Reply-To domain differs from sender",
            15,
            f"From: {sender}; Reply-To: {reply}",
            "Replies would be delivered to a different registrable domain; legitimate workflows can also do this.",
        )
    display = parseaddr(sender)[0]
    display_domains = re.findall(r"[\w-]+\.[a-z]{2,}", display, re.I)
    if any(base_domain(d) != base_domain(sender_domain) for d in display_domains):
        flag(
            "display_spoof",
            "Display-name domain mismatch",
            15,
            sender,
            "A domain in the display name differs from the sender domain.",
        )
    if re.search(r"microsoft|paypal|apple|google|amazon", display, re.I) and not any(
        base_domain(sender_domain) == d
        for d in {
            "microsoft.com",
            "paypal.com",
            "apple.com",
            "google.com",
            "amazon.com",
        }
    ):
        flag(
            "brand_impersonation",
            "Brand impersonation indicator",
            15,
            sender,
            "Display name claims a recognized brand while the sender uses another domain. Delegated senders remain possible.",
        )
    if "xn--" in sender_domain or re.search(r"\d{5,}", sender_domain):
        flag(
            "sender_obfuscation",
            "Unusual sender domain",
            8,
            sender_domain,
            "Punycode or a long numeric sequence warrants analyst review; not proof of abuse.",
        )
    auth_headers = [str(v) for v in msg.get_all("Authentication-Results", [])]
    authentication = {}
    for method in ("spf", "dkim", "dmarc"):
        matches = re.findall(
            rf"\b{method}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b",
            "\n".join(auth_headers),
            re.I,
        )
        status = (
            matches[0].lower()
            if len(set(m.lower() for m in matches)) == 1
            else "inconclusive"
            if matches
            else "unavailable"
        )
        authentication[method] = {
            "result": status,
            "evidence": auth_headers,
            "trust": "Reported by supplied headers; header provenance is not independently verified.",
        }
        if status in {"fail", "softfail"}:
            flag(
                f"auth_{method}",
                f"{method.upper()} reported {status}",
                {"spf": 8, "dkim": 8, "dmarc": 12}[method],
                "\n".join(auth_headers),
                "The supplied Authentication-Results header explicitly reports this result; it may be forged.",
            )
    subject = str(msg.get("Subject", ""))
    urgent = re.findall(
        r"\b(urgent|immediately|suspend\w*|final warning|action required|overdue)\b",
        subject + " " + all_text,
        re.I,
    )
    if urgent:
        flag(
            "urgency",
            "Pressure and urgency language",
            10,
            ", ".join(sorted(set(urgent))),
            "Time pressure can encourage a recipient to bypass verification.",
        )
    if re.search(
        r"verify.{0,40}(account|password)|password|sign.?in|log.?in|credential",
        all_text,
        re.I,
    ):
        flag(
            "credential_lure",
            "Potential credential request",
            12,
            all_text[:450],
            "Message requests account or credential interaction; credential theft is a hypothesis, not a confirmed outcome.",
        )
    if (
        re.search(r"(pay|payment|bank details|invoice)", all_text + subject, re.I)
        and urgent
    ):
        flag(
            "payment_pressure",
            "Urgent financial request",
            12,
            subject,
            "Financial language combined with pressure warrants out-of-band verification.",
        )
    urls = [(m.group(), "Email text") for m in URL_RE.finditer(body_plain)]
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"])
        if href.lower().startswith(("http://", "https://")):
            urls.append((href, "HTML href"))
            shown = anchor.get_text(" ", strip=True)
            if (
                shown.lower().startswith(("https://", "http://"))
                and urlsplit(shown).hostname != urlsplit(href).hostname
            ):
                flag(
                    "link_mismatch",
                    "Link text disguises destination",
                    15,
                    f"Displayed: {shown}; actual: {href}",
                    "Visible link text and destination hostnames differ.",
                )
        if any(
            re.search(
                r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0",
                str(p.get("style", "")),
                re.I,
            )
            or p.has_attr("hidden")
            for p in [anchor, *list(anchor.parents)[:20]]
        ):
            flag(
                "hidden_link",
                "Hidden HTML link",
                8,
                href,
                "The link or an ancestor has a hiding style or hidden attribute.",
            )
    if soup.find(["script", "form", "iframe", "object", "embed"]) or soup.find(
        "meta", attrs={"http-equiv": re.compile("refresh", re.I)}
    ):
        flag(
            "active_html",
            "Active HTML content",
            12,
            "script/form/iframe/object/embed/meta-refresh element",
            "Active content is present. PhishScope renders a text-only representation.",
        )
    for value, source in set(urls):
        value = value.rstrip(".,;)")
        try:
            parsed = urlsplit(value)
            host = parsed.hostname or ""
            ioc(value, "url", source)
            ioc(host, "domain", source)
            try:
                ip = ipaddress.ip_address(host)
                ioc(str(ip), "ipv4" if ip.version == 4 else "ipv6", source)
                flag(
                    "ip_url",
                    "IP address in URL",
                    12,
                    value,
                    "A literal IP address is used in place of a domain; this can obscure ownership.",
                )
            except ValueError:
                pass
            if parsed.username or "xn--" in host or "%" in parsed.netloc:
                flag(
                    "obfuscated_url",
                    "Obfuscated URL authority",
                    12,
                    value,
                    "User-info, encoded authority or punycode may disguise the destination.",
                )
            if host in {"bit.ly", "t.co", "tinyurl.com", "short.example"}:
                flag(
                    "short_url",
                    "Shortened URL",
                    10,
                    value,
                    "A shortening host hides the final destination; no redirect was followed.",
                )
            for key, values in parse_qs(parsed.query).items():
                if key.lower() in {
                    "url",
                    "redirect",
                    "redirect_uri",
                    "next",
                    "target",
                    "continue",
                }:
                    for target in values:
                        target = unquote(target)
                        if target.lower().startswith(("http://", "https://")):
                            ioc(
                                target,
                                "url",
                                "Redirect query metadata",
                                "Embedded redirect target; not fetched or confirmed",
                            )
                            ioc(
                                urlsplit(target).hostname or "",
                                "domain",
                                "Redirect query metadata",
                            )
                            flag(
                                "redirect_metadata",
                                "External redirect target in URL",
                                8,
                                f"{value} -> {target}",
                                "A URL-valued redirect parameter is present; actual server behavior is unverified.",
                            )
        except ValueError:
            flag(
                "invalid_url",
                "Malformed URL",
                5,
                value,
                "URL structure could not be parsed reliably.",
            )
    corpus = raw.decode("utf-8", errors="replace") + "\n" + all_text
    for address in EMAIL_RE.findall(corpus):
        ioc(address, "email", "Headers/body")
        ioc(address.rsplit("@", 1)[-1], "domain", "Email address")
    for value in re.findall(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]{0,39}(?![\w:])",
        corpus,
    ):
        try:
            ip = ipaddress.ip_address(value)
            ioc(str(ip), "ipv4" if ip.version == 4 else "ipv6", "Headers/body")
        except ValueError:
            pass
    for value in re.findall(
        r"(?<![\w])(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![\w])", corpus
    ):
        ioc(value, {32: "md5", 40: "sha1", 64: "sha256"}[len(value)], "Headers/body")
    for value in re.findall(
        r"(?<![\w@.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w.-])",
        all_text,
    ):
        ioc(value.lower(), "domain", "Body text")
    for name in ("From", "Subject", "Message-ID", "Date"):
        if len(msg.get_all(name, [])) > 1:
            flag(
                "duplicate_header",
                f"Duplicate {name} header",
                8,
                str(msg.get_all(name)),
                "Duplicate singleton headers may cause inconsistent interpretation.",
            )
    if msg.defects:
        flag(
            "parser_defect",
            "Email structure inconsistencies",
            5,
            str(msg.defects),
            "The MIME parser recorded structural defects.",
        )
    if not msg.get("Message-ID") or not msg.get("Date"):
        flag(
            "missing_headers",
            "Missing message provenance headers",
            3,
            "Date or Message-ID absent",
            "Incomplete headers reduce provenance confidence.",
        )
    # Repeated HTML links and MIME parts must not amplify a single risk factor.
    factors = {}
    for finding in findings:
        factors.setdefault(finding["code"], finding)
    score = min(100, sum(f["points"] for f in factors.values()))
    severity = classify_risk(score)
    mappings = []

    def mapping(tid, state, evidence, reason):
        technique = next(t for t in TECHNIQUES if t["id"] == tid)
        mappings.append(
            {
                **technique,
                "state": state,
                "confidence": "medium" if state == "suspected" else "low",
                "evidence": evidence,
                "justification": reason,
            }
        )

    if score >= 25:
        mapping(
            "T1566",
            "suspected",
            [f["id"] for f in findings],
            "Multiple local indicators are consistent with a phishing attempt; attribution and intent remain unverified.",
        )
        if urls:
            mapping(
                "T1566.002",
                "suspected",
                [v for v, _ in urls][:5],
                "Links occur in a message with corroborating suspicious findings.",
            )
        if attachments and "risky_attachment" in factors:
            mapping(
                "T1566.001",
                "suspected",
                [a["filename"] for a in attachments],
                "Active attachment extensions and suspicious message context support an attachment phishing hypothesis.",
            )
            mapping(
                "T1204.002",
                "unverified hypothesis",
                [a["filename"] for a in attachments],
                "Opening the file could enable execution. No endpoint telemetry or user action is available.",
            )
        # Credential-only lures do not establish the execution semantics of T1204.001.
        if urls and re.search(r"download|install|execute|run the", all_text, re.I):
            mapping(
                "T1204.001",
                "unverified hypothesis",
                [v for v, _ in urls][:5],
                "The message requests an execution-related action through a link. No click or execution is observed.",
            )
    recommendations = []

    def recommend(phase, action, reason, evidence):
        recommendations.append(
            {"phase": phase, "action": action, "reason": reason, "evidence": evidence}
        )

    if findings:
        refs = [f["id"] for f in findings]
        recommend(
            "Preparation",
            "Review email authentication enforcement and awareness training.",
            "Observed anomalies provide concrete examples for control review.",
            refs,
        )
        recommend(
            "Containment",
            "Quarantine this message for review and identify other recipients before taking broader action.",
            "Local findings warrant triage; unverified infrastructure should not be automatically blocked.",
            refs,
        )
        recommend(
            "Eradication",
            "After validation, remove matching confirmed malicious messages.",
            "Preserve original evidence and confirm scope first.",
            refs,
        )
        recommend(
            "Recovery",
            "Ask whether the recipient interacted; reset credentials only if exposure is established.",
            "The email alone contains no evidence of compromise.",
            refs,
        )
        recommend(
            "Lessons Learned",
            "Document verified patterns and review matching detection rules.",
            "Use evidence-backed patterns while recording false-positive possibilities.",
            refs,
        )
    else:
        recommend(
            "Lessons Learned",
            "Record the assessment and close after analyst review.",
            "No configured local risk factors were detected; this does not guarantee safety.",
            [],
        )
    limitations = [
        "Local heuristic assessment — not externally verified.",
        "Authentication-Results headers can be forged; their receiving gateway provenance is unverified.",
        "No URLs were fetched, redirects followed, DNS lookups performed, or attachments executed.",
        "No click, execution, credential exposure or successful compromise is established.",
        "Sender/domain reputation is unknown until an explicit external lookup; lack of detections does not establish safety.",
    ]
    parsed = {
        "sender": sender,
        "recipient": ", ".join(str(x) for x in msg.get_all("To", [])),
        "reply_to": reply,
        "subject": subject,
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "received": [str(x) for x in msg.get_all("Received", [])],
        "headers": [{"name": k, "value": str(v)} for k, v in msg.items()],
        "authentication": authentication,
        "plain_text": body_plain,
        "html_body": body_html,
        "html_text": soup.get_text("\n", strip=True),
        "attachments": attachments,
        "mime": mime,
    }
    return {
        "engine_version": "1.0.0",
        "analyzed_at": timestamp,
        "parsed": parsed,
        "findings": findings,
        "iocs": list(indicators.values()),
        "mappings": mappings,
        "risk": {
            "score": score,
            "severity": severity,
            "factors": list(factors.values()),
            "confidence": "medium" if findings else "low",
            "reasoning": "Sum of unique local risk factors, capped at 100. Thresholds are application-defined: 0–24 low, 25–49 medium, 50–74 high, 75–100 critical.",
            "compromise": "No evidence of successful compromise",
            "limitations": limitations,
        },
        "recommendations": recommendations,
        "limitations": limitations,
    }

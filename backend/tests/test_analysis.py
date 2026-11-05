import hashlib
from email.message import EmailMessage
import pytest

from backend.analysis import analyze, MAX_EMAIL, safe_filename, classify_risk
from backend.samples import SAMPLES


def fixture(key):
    return next(s["raw_email"].encode() for s in SAMPLES if s["id"] == key)


def test_parsing_headers_authentication_and_safe_body():
    a = analyze(fixture("account"))
    assert "Microsoft" in a["parsed"]["sender"]
    assert "analyst@company.example" in a["parsed"]["recipient"]
    assert a["parsed"]["message_id"]
    assert len(a["parsed"]["received"]) == 1
    assert a["parsed"]["authentication"]["spf"]["result"] == "fail"
    assert "HTML" not in a["parsed"]["html_text"]
    codes = {f["code"] for f in a["findings"]}
    assert {
        "reply_mismatch",
        "brand_impersonation",
        "link_mismatch",
        "hidden_link",
        "credential_lure",
        "redirect_metadata",
    } <= codes
    assert all(f["evidence"] and f["reason"] for f in a["findings"])


def test_missing_and_conflicting_auth_are_not_failures():
    raw = b"From: x@sample.test\nSubject: Hello\nAuthentication-Results: gate; spf=pass\nAuthentication-Results: gate; spf=fail\n\nHello"
    a = analyze(raw)
    assert a["parsed"]["authentication"]["spf"]["result"] == "inconclusive"
    assert a["parsed"]["authentication"]["dmarc"]["result"] == "unavailable"
    assert not any(f["code"].startswith("auth_") for f in a["findings"])


def test_ip_hash_domain_extraction_and_deduplication():
    raw = (
        b"From: sender@example.test\nSubject: Check\n\nhttps://192.0.2.1/x https://192.0.2.1/x 2001:db8::1 "
        + b"a" * 64
        + b" "
        + b"b" * 40
        + b" "
        + b"c" * 32
        + b" domain.example"
    )
    a = analyze(raw)
    pairs = [(i["type"], i["value"]) for i in a["iocs"]]
    assert len(pairs) == len(set(pairs))
    assert ("ipv4", "192.0.2.1") in pairs
    assert ("ipv6", "2001:db8::1") in pairs
    assert ("sha256", "a" * 64) in pairs
    assert ("sha1", "b" * 40) in pairs
    assert ("md5", "c" * 32) in pairs
    assert ("domain", "domain.example") in pairs
    assert all(i["evidence"] for i in a["iocs"])


def test_attachment_metadata_hashes_and_mapping():
    a = analyze(fixture("invoice"))
    att = a["parsed"]["attachments"][0]
    assert att["filename"] == "Invoice.pdf.exe"
    assert (
        att["sha256"]
        == hashlib.sha256(b"INERT SIMULATION TEXT; NOT AN EXECUTABLE").hexdigest()
    )
    assert {"risky_attachment", "double_extension", "mime_mismatch"} <= {
        f["code"] for f in a["findings"]
    }
    mappings = {m["id"]: m for m in a["mappings"]}
    assert "T1566.001" in mappings
    assert "T1566.002" not in mappings
    assert mappings["T1204.002"]["state"] == "unverified hypothesis"


def test_credential_link_does_not_establish_execution():
    a = analyze(fixture("account"))
    assert "T1566.002" in {m["id"] for m in a["mappings"]}
    assert "T1204.001" not in {m["id"] for m in a["mappings"]}
    assert all(m["evidence"] and m["justification"] for m in a["mappings"])


def test_execution_link_hypothesis_requires_execution_language():
    a = analyze(
        b"From: a@x.example\nSubject: Urgent action required\nReply-To: b@y.example\n\nDownload and install immediately from https://files.example/setup.exe"
    )
    assert any(
        m["id"] == "T1204.001" and m["state"] == "unverified hypothesis"
        for m in a["mappings"]
    )


@pytest.mark.parametrize("key", ["account", "invoice", "delivery"])
def test_phishing_samples_have_explainable_risk(key):
    a = analyze(fixture(key))
    risk = a["risk"]
    assert risk["score"] == min(100, sum(f["points"] for f in risk["factors"]))
    assert risk["severity"] in {"high", "critical"}
    assert risk["compromise"] == "No evidence of successful compromise"
    assert len(a["recommendations"]) == 5


def test_benign_email_has_no_phishing_mapping():
    a = analyze(fixture("benign"))
    assert a["risk"]["score"] == 0
    assert a["risk"]["severity"] == "low"
    assert not a["mappings"]
    assert not a["findings"]


@pytest.mark.parametrize(
    "raw", [b"not an email", b"MZbinary", b"\0bad", b"A" * (MAX_EMAIL + 1)]
)
def test_invalid_emails_rejected(raw):
    with pytest.raises(ValueError):
        analyze(raw)


def test_attachment_name_does_not_escape_storage():
    assert safe_filename("../../evil.exe") == "evil.exe"
    assert safe_filename("C:\\unsafe\\evil.exe") == "evil.exe"


@pytest.mark.parametrize(
    "score,severity",
    [
        (0, "low"),
        (24, "low"),
        (25, "medium"),
        (49, "medium"),
        (50, "high"),
        (74, "high"),
        (75, "critical"),
        (100, "critical"),
    ],
)
def test_risk_threshold_boundaries(score, severity):
    assert classify_risk(score) == severity


def test_envelope_sender_mismatch_is_qualified_evidence():
    a = analyze(
        b"From: a@company.example\nReturn-Path: bounce@mailer.example\nSubject: Update\n\nHello"
    )
    finding = next(f for f in a["findings"] if f["code"] == "envelope_mismatch")
    assert "legitimately" in finding["reason"]


def test_duplicate_links_do_not_amplify_risk():
    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg["Subject"] = "Normal"
    msg.set_content("Please review")
    msg.add_alternative(
        '<a href="https://one.example">https://other.example</a>' * 12, subtype="html"
    )
    result = analyze(msg.as_bytes())
    assert (
        sum(
            f["points"]
            for f in result["risk"]["factors"]
            if f["code"] == "link_mismatch"
        )
        == 15
    )

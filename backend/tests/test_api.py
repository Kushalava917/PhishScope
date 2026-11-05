import base64
import hashlib
import io

import pytest
from pypdf import PdfReader
from sqlalchemy import select

from backend.db import Indicator, Investigation, Revision, SessionLocal


def create(client, key="account"):
    response = client.post(f"/api/samples/{key}")
    assert response.status_code == 201, response.text
    return response.json()


def test_health_empty_metrics_and_seed_idempotency(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/dashboard").json()["total"] == 0
    assert len(client.post("/api/demo").json()["created"]) == 4
    assert client.post("/api/demo").json()["created"] == []
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["total"] == 4
    assert dashboard["completed"] == 4
    assert dashboard["severities"]["low"] == 1
    assert dashboard["confirmed_malicious"] == 0


def test_persistence_notes_revisions_exact_evidence_and_cascade(client):
    c = create(client)
    cid = c["id"]
    with SessionLocal() as db:
        record = db.get(Investigation, cid)
        assert (
            record.evidence_sha256
            == hashlib.sha256(base64.b64decode(record.original_base64)).hexdigest()
        )
        assert (
            len(
                db.scalars(
                    select(Indicator).where(Indicator.investigation_id == cid)
                ).all()
            )
            == c["ioc_count"]
        )
    original = client.get(f"/api/investigations/{cid}/evidence").content
    assert hashlib.sha256(original).hexdigest() == c["evidence_sha256"]
    assert (
        client.patch(
            f"/api/investigations/{cid}", json={"notes": "Verified analyst note"}
        ).status_code
        == 200
    )
    rerun = client.post(f"/api/investigations/{cid}/reanalyze").json()
    assert len(rerun["revisions"]) == 2
    assert rerun["notes"] == "Verified analyst note"
    assert rerun["evidence_sha256"] == c["evidence_sha256"]
    assert (
        client.get(f"/api/investigations/{cid}/revisions/{c['revision_id']}").json()
        == c["analysis"]
    )
    assert client.delete(f"/api/investigations/{cid}").status_code == 204
    assert client.get(f"/api/investigations/{cid}").status_code == 404
    with SessionLocal() as db:
        assert not db.scalars(select(Revision)).all()
        assert not db.scalars(select(Indicator)).all()


def test_all_report_sections_and_export_contents(client):
    c = create(client)
    cid = c["id"]
    client.patch(
        f"/api/investigations/{cid}", json={"notes": "Evidence checked by test analyst"}
    )
    preview = client.get(f"/api/investigations/{cid}/report").json()
    assert len(preview["sections"]) == 18  # Plus the separate cover page.
    response = client.get(f"/api/investigations/{cid}/report/pdf")
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")
    reader = PdfReader(io.BytesIO(response.content))
    text = "\n".join(page.extract_text() for page in reader.pages)
    for expected in [
        "Incident Investigation Report",
        "Executive Summary",
        "MITRE ATT&CK",
        "T1566.002",
        "verify-account.example",
        c["evidence_sha256"],
        "Evidence checked by test analyst",
        "CONFIDENTIAL",
        "Page 1",
        "Limitations and Unverified Findings",
    ]:
        assert expected in text
    assert len(reader.pages) > 2
    assert client.get(f"/api/investigations/{cid}/report/md").text.startswith(
        "# PhishScope"
    )
    exported = client.get(f"/api/investigations/{cid}/report/json").json()
    assert exported["investigation"]["analysis"]["risk"]["score"] == c["risk"]["score"]
    assert len(client.get(f"/api/investigations/{cid}").json()["exports"]) == 3


def test_upload_preserves_non_utf8_bytes(client):
    original = b"From: a@example.test\r\nSubject: Test\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9"
    response = client.post(
        "/api/upload", files={"file": ("../../message.eml", original, "message/rfc822")}
    )
    assert response.status_code == 201
    c = response.json()
    assert c["name"] == "message.eml"
    assert client.get(f"/api/investigations/{c['id']}/evidence").content == original
    assert "café" in c["analysis"]["parsed"]["plain_text"]


@pytest.mark.parametrize(
    "filename,payload,mime,status",
    [
        ("bad.exe", b"MZ", "application/octet-stream", 415),
        ("bad.eml", b"MZbinary", "message/rfc822", 422),
        ("bad.eml", b"Not an email", "message/rfc822", 422),
        ("bad.eml", b"From: a@b.test\nSubject: x\n\nhello", "image/png", 415),
        ("big.eml", b"x" * (5 * 1024 * 1024 + 1), "text/plain", 413),
    ],
)
def test_upload_security(client, filename, payload, mime, status):
    assert (
        client.post(
            "/api/upload", files={"file": (filename, payload, mime)}
        ).status_code
        == status
    )


def test_api_validation_and_cross_origin_protection(client):
    assert (
        client.post(
            "/api/investigations", json={"name": "x", "raw_email": "x"}
        ).status_code
        == 422
    )
    assert (
        client.post("/api/demo", headers={"Origin": "https://evil.example"}).status_code
        == 403
    )
    assert (
        client.post("/api/demo", headers={"Sec-Fetch-Site": "cross-site"}).status_code
        == 403
    )
    assert (
        client.get("/api/dashboard", headers={"Host": "evil.example"}).status_code
        == 400
    )
    assert client.get("/api/health").headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/health").headers["cache-control"] == "no-store"
    assert (
        client.post(
            "/api/investigations", content=b"x" * (8 * 1024 * 1024 + 1)
        ).status_code
        == 413
    )


def test_search_filters_exports_and_settings(client):
    c = create(client)
    create(client, "benign")
    assert len(client.get("/api/investigations?q=account").json()) == 1
    assert len(client.get("/api/investigations?severity=low").json()) == 1
    rows = client.get(f"/api/iocs?case_id={c['id']}&type=url&sort=type").json()
    assert rows and all(r["type"] == "url" for r in rows)
    assert client.get("/api/iocs?q=nothing-matches").json() == []
    assert (
        client.get("/api/iocs/export/csv")
        .headers["content-type"]
        .startswith("text/csv")
    )
    assert client.get("/api/iocs/export/json").json()
    prefs = {
        "analyst_name": "Jamie",
        "classification": "INTERNAL",
        "organization": "Test SOC",
        "default_input": "sample",
    }
    assert client.patch("/api/settings", json=prefs).json()["preferences"] == prefs
    assert client.get("/api/settings").json()["preferences"] == prefs
    assert len(client.get("/api/techniques").json()) == 5


def test_simulation_lookup_blocked_and_consent_required(client):
    c = create(client)
    body = {
        "provider": "virustotal",
        "indicator_id": c["analysis"]["iocs"][0]["id"],
        "consent": True,
    }
    assert (
        client.post(f"/api/investigations/{c['id']}/lookup", json=body).status_code
        == 422
    )
    body["consent"] = False
    assert (
        client.post(f"/api/investigations/{c['id']}/lookup", json=body).status_code
        == 422
    )


def test_provider_keys_are_never_exposed(client, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "secret-123-test-key")
    response = client.get("/api/settings")
    assert "secret-123" not in response.text
    assert response.json()["providers"][0]["configured"]


def test_markdown_tables_and_pdf_markup_are_escaped(client):
    raw = "From: a@example.test\nSubject: <b>not markup</b>\n\n<script>inert</script>"
    c = client.post(
        "/api/investigations", json={"name": "<script>inert</script>", "raw_email": raw}
    ).json()
    markdown = client.get(f"/api/investigations/{c['id']}/report/md").text
    assert "| --- | --- |" in markdown
    pdf = client.get(f"/api/investigations/{c['id']}/report/pdf")
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "<b>not markup</b>" in text


def test_provider_results_persist_in_ioc_view_and_cache(client, monkeypatch):
    from backend.analysis import now

    calls = []

    def fixture_lookup(provider, value, kind):
        calls.append(value)
        return {
            "provider": provider,
            "indicator": value,
            "checked_at": now(),
            "status": "ok",
            "reputation": "malicious",
            "source_url": "https://www.virustotal.com/",
            "detections": {"malicious": 2},
            "message": "Explicit mocked provider response for adapter persistence test",
        }

    monkeypatch.setattr("backend.main.lookup", fixture_lookup)
    c = client.post(
        "/api/investigations",
        json={
            "name": "Provider persistence test",
            "raw_email": "From: a@sender.example\nSubject: Review\n\nhttps://public.com/",
        },
    ).json()
    indicator = next(i for i in c["analysis"]["iocs"] if i["type"] == "url")
    body = {"provider": "virustotal", "indicator_id": indicator["id"], "consent": True}
    path = f"/api/investigations/{c['id']}"
    assert client.post(path + "/lookup", json=body).json()["status"] == "ok"
    assert client.post(path + "/lookup", json=body).json()["cached"]
    assert len(calls) == 1
    row = next(
        i
        for i in client.get("/api/iocs", params={"case_id": c["id"]}).json()
        if i["id"] == indicator["id"]
    )
    assert row["reputation"] == "malicious"
    assert row["lookups"][0]["detections"]["malicious"] == 2
    assert client.get("/api/dashboard").json()["confirmed_malicious"] == 1
    assert client.get(path).json()["risk"]["score"] == c["risk"]["score"]
    assert (
        "Explicit mocked provider response"
        in client.get(path + "/report").json()["markdown"]
    )

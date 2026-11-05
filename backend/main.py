import base64
import csv
import hashlib
import io
import json
import os
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import reports
from .analysis import MAX_EMAIL, analyze, now, safe_filename
from .db import (
    Indicator,
    Intelligence,
    Investigation,
    ReportExport,
    Revision,
    Setting,
    engine,
    get_db,
)
from .intelligence import PROVIDERS, lookup
from .samples import SAMPLES
from .techniques import TECHNIQUES

DEFAULT_SETTINGS = {
    "analyst_name": "SOC Analyst",
    "classification": "CONFIDENTIAL",
    "organization": "Local SOC workspace",
    "default_input": "paste",
}
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", "http://127.0.0.1:3000,http://localhost:3000,http://testserver"
).split(",")


@asynccontextmanager
async def lifespan(app):
    # Versioned schema managed by Alembic, including on an empty installation.
    from alembic.config import Config
    from alembic import command

    command.upgrade(Config("alembic.ini"), "head")
    yield


app = FastAPI(title="PhishScope", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv(
        "ALLOWED_HOSTS", "127.0.0.1,localhost,testserver,backend"
    ).split(","),
)


class RequestGuard:
    """Enforce limits before multipart/JSON parsers allocate unbounded memory."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        if scope["method"] in {"POST", "PATCH", "DELETE", "PUT"}:
            origin = headers.get(b"origin", b"").decode()
            if (origin and origin not in ALLOWED_ORIGINS) or headers.get(
                b"sec-fetch-site"
            ) == b"cross-site":
                return await Response("Cross-origin write rejected", 403)(
                    scope, receive, send
                )
            chunks, size = [], 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                size += len(message.get("body", b""))
                if size > 8 * 1024 * 1024:
                    return await Response("Request exceeds 8 MiB", 413)(
                        scope, receive, send
                    )
                chunks.append(message.get("body", b""))
                if not message.get("more_body"):
                    break
            data = b"".join(chunks)
            consumed = False

            async def replay():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": data, "more_body": False}
                return await receive()

            await self.app(scope, replay, send)
        else:
            await self.app(scope, receive, send)


app.add_middleware(RequestGuard)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        }
    )
    return response


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Submission(StrictModel):
    name: str = Field(default="Email investigation", min_length=1, max_length=200)
    raw_email: str = Field(min_length=10, max_length=MAX_EMAIL)


class Notes(StrictModel):
    notes: str = Field(max_length=20000)


class SettingsInput(StrictModel):
    analyst_name: str = Field(min_length=1, max_length=100)
    classification: Literal["CONFIDENTIAL", "INTERNAL", "PUBLIC"]
    organization: str = Field(min_length=1, max_length=200)
    default_input: Literal["paste", "upload", "sample"]


class LookupInput(StrictModel):
    provider: Literal["virustotal", "urlscan", "abuseipdb", "safebrowsing"]
    indicator_id: str = Field(min_length=1, max_length=40)
    consent: Literal[True]


def get_case(db, case_id):
    case = db.get(Investigation, case_id)
    if case is None:
        raise HTTPException(404, "Investigation not found")
    return case


def latest(db, case_id):
    return db.scalars(
        select(Revision)
        .where(Revision.investigation_id == case_id)
        .order_by(Revision.created_at.desc(), Revision.id.desc())
    ).first()


def save_revision(db, case, result):
    revision = Revision(investigation_id=case.id, result=result)
    db.add(revision)
    db.flush()
    for indicator in result["iocs"]:
        db.add(
            Indicator(
                investigation_id=case.id,
                revision_id=revision.id,
                value=indicator["value"],
                type=indicator["type"],
                detail=indicator,
            )
        )
    return revision


def summary(case, rev):
    return {
        "id": case.id,
        "name": case.name,
        "created_at": case.created_at,
        "simulation": case.simulation,
        "status": case.status,
        "subject": rev.result["parsed"]["subject"],
        "sender": rev.result["parsed"]["sender"],
        "risk": rev.result["risk"],
        "ioc_count": len(rev.result["iocs"]),
        "finding_count": len(rev.result["findings"]),
    }


def detail(db, case):
    revision = latest(db, case.id)
    return {
        **summary(case, revision),
        "raw_email": case.raw_email,
        "evidence_sha256": case.evidence_sha256,
        "notes": case.notes,
        "revision_id": revision.id,
        "analysis": revision.result,
        "revisions": [
            {
                "id": r.id,
                "created_at": r.created_at,
                "engine_version": r.result["engine_version"],
            }
            for r in db.scalars(
                select(Revision)
                .where(Revision.investigation_id == case.id)
                .order_by(Revision.created_at)
            )
        ],
        "intelligence": [
            r.result
            for r in db.scalars(
                select(Intelligence)
                .where(Intelligence.investigation_id == case.id)
                .order_by(Intelligence.checked_at.desc())
            )
        ],
        "exports": [
            {
                "id": r.id,
                "format": r.format,
                "created_at": r.created_at,
                "revision_id": r.revision_id,
                "sha256": r.content_sha256,
            }
            for r in db.scalars(
                select(ReportExport)
                .where(ReportExport.investigation_id == case.id)
                .order_by(ReportExport.created_at.desc())
            )
        ],
    }


def create_case(db, raw, name, sample_id=None):
    try:
        result = analyze(raw)
    except (ValueError, RecursionError) as error:
        raise HTTPException(
            422,
            str(error)
            if isinstance(error, ValueError)
            else "Email MIME nesting is too deep",
        ) from error
    case = Investigation(
        name=name,
        raw_email=raw.decode("utf-8", errors="replace"),
        original_base64=base64.b64encode(raw).decode(),
        evidence_sha256=hashlib.sha256(raw).hexdigest(),
        simulation=sample_id is not None,
        sample_id=sample_id,
    )
    db.add(case)
    db.flush()
    save_revision(db, case, result)
    db.commit()
    return detail(db, case)


def settings(db):
    stored = db.get(Setting, "preferences")
    return {**DEFAULT_SETTINGS, **(stored.value if stored else {})}


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(Setting).limit(1))
    return {"status": "ok", "version": "1.0.0", "mode": "local"}


@app.get("/api/samples")
def samples():
    return SAMPLES


@app.post("/api/samples/{sample_id}", status_code=201)
def investigate_sample(sample_id: str, db: Session = Depends(get_db)):
    sample = next((s for s in SAMPLES if s["id"] == sample_id), None)
    if not sample:
        raise HTTPException(404, "Sample not found")
    return create_case(db, sample["raw_email"].encode(), sample["name"], sample_id)


@app.post("/api/demo", status_code=201)
def seed_demo(db: Session = Depends(get_db)):
    existing = set(db.scalars(select(Investigation.sample_id)).all())
    created = [
        create_case(db, s["raw_email"].encode(), s["name"], s["id"])["id"]
        for s in SAMPLES
        if s["id"] not in existing
    ]
    return {"created": created}


@app.post("/api/investigations", status_code=201)
def create(submission: Submission, db: Session = Depends(get_db)):
    return create_case(db, submission.raw_email.encode(), submission.name)


@app.post("/api/upload", status_code=201)
async def upload(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = safe_filename(file.filename or "")
    if not filename.lower().endswith((".eml", ".txt")):
        raise HTTPException(415, "Only .eml and .txt email files are accepted")
    if file.content_type not in {
        "message/rfc822",
        "text/plain",
        "application/octet-stream",
        "text/x-eml",
    }:
        raise HTTPException(415, "Unsupported upload MIME type")
    raw = await file.read(MAX_EMAIL + 1)
    await file.close()
    if len(raw) > MAX_EMAIL:
        raise HTTPException(413, "Email exceeds the 5 MiB limit")
    return create_case(db, raw, filename)


@app.get("/api/investigations")
def investigations(q: str = "", severity: str = "", db: Session = Depends(get_db)):
    cases = db.scalars(
        select(Investigation).order_by(Investigation.created_at.desc())
    ).all()
    rows = [summary(c, latest(db, c.id)) for c in cases]
    return [
        r
        for r in rows
        if (
            not q
            or q.lower() in (r["name"] + r["subject"] + r["sender"] + r["id"]).lower()
        )
        and (not severity or r["risk"]["severity"] == severity)
    ]


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)):
    rows = investigations(db=db)
    severities = Counter(r["risk"]["severity"] for r in rows)
    indicators = []
    for row in rows:
        indicators.extend(latest(db, row["id"]).result["iocs"])
    malicious = set(
        (i.indicator, i.investigation_id)
        for i in db.scalars(select(Intelligence))
        if i.result.get("status") == "ok" and i.result.get("reputation") == "malicious"
    )
    return {
        "total": len(rows),
        "completed": sum(r["status"] == "completed" for r in rows),
        "pending": sum(r["status"] == "pending" for r in rows),
        "confirmed_malicious": len(malicious),
        "severities": {k: severities[k] for k in ["critical", "high", "medium", "low"]},
        "ioc_categories": dict(Counter(i["type"] for i in indicators)),
        "timeline": [
            {
                "date": (datetime.now(timezone.utc) - timedelta(days=d))
                .date()
                .isoformat(),
                "investigations": sum(
                    r["created_at"][:10]
                    == (datetime.now(timezone.utc) - timedelta(days=d))
                    .date()
                    .isoformat()
                    for r in rows
                ),
            }
            for d in reversed(range(7))
        ],
        "recent": rows[:8],
    }


@app.get("/api/investigations/{case_id}")
def investigation(case_id: str, db: Session = Depends(get_db)):
    return detail(db, get_case(db, case_id))


@app.get("/api/investigations/{case_id}/evidence")
def evidence(case_id: str, db: Session = Depends(get_db)):
    case = get_case(db, case_id)
    return Response(
        base64.b64decode(case.original_base64),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{case.id}-evidence.eml"'
        },
    )


@app.get("/api/investigations/{case_id}/revisions/{revision_id}")
def revision(case_id: str, revision_id: str, db: Session = Depends(get_db)):
    get_case(db, case_id)
    result = db.get(Revision, revision_id)
    if not result or result.investigation_id != case_id:
        raise HTTPException(404, "Revision not found")
    return result.result


@app.patch("/api/investigations/{case_id}")
def notes(case_id: str, body: Notes, db: Session = Depends(get_db)):
    case = get_case(db, case_id)
    case.notes = body.notes
    db.commit()
    return detail(db, case)


@app.post("/api/investigations/{case_id}/reanalyze")
def reanalyze(case_id: str, db: Session = Depends(get_db)):
    case = get_case(db, case_id)
    save_revision(db, case, analyze(base64.b64decode(case.original_base64)))
    db.commit()
    return detail(db, case)


@app.delete("/api/investigations/{case_id}", status_code=204)
def remove(case_id: str, db: Session = Depends(get_db)):
    db.delete(get_case(db, case_id))
    db.commit()


@app.get("/api/iocs")
def iocs(
    q: str = "",
    type: str = "",
    case_id: str = "",
    sort: Literal["value", "type", "first_observed"] = "value",
    db: Session = Depends(get_db),
):
    rows = []
    cases = (
        [get_case(db, case_id)] if case_id else db.scalars(select(Investigation)).all()
    )
    for case in cases:
        history = [
            record.result
            for record in db.scalars(
                select(Intelligence)
                .where(Intelligence.investigation_id == case.id)
                .order_by(Intelligence.checked_at.desc())
            )
        ]
        for i in latest(db, case.id).result["iocs"]:
            lookups = [
                result for result in history if result["indicator"] == i["value"]
            ]
            current = {}
            for result in lookups:
                current.setdefault(result["provider"], result)
            reputations = {
                result["reputation"]
                for result in current.values()
                if result["status"] == "ok"
            }
            reputation = next(
                (
                    value
                    for value in ("malicious", "reported_abuse", "no_detections")
                    if value in reputations
                ),
                "unverified",
            )
            rows.append(
                {
                    **i,
                    "reputation": reputation,
                    "lookups": lookups,
                    "investigation_id": case.id,
                    "investigation_name": case.name,
                    "simulation": case.simulation,
                }
            )
    return sorted(
        [
            i
            for i in rows
            if (not q or q.lower() in i["value"].lower())
            and (not type or i["type"] == type)
        ],
        key=lambda i: i[sort],
    )


@app.get("/api/iocs/export/{format}")
def export_iocs(
    format: Literal["csv", "json"],
    q: str = "",
    type: str = "",
    case_id: str = "",
    db: Session = Depends(get_db),
):
    rows = iocs(q=q, type=type, case_id=case_id, db=db)
    if format == "json":
        content = json.dumps(rows, indent=2).encode()
    else:
        output = io.StringIO(newline="")
        fields = [
            "value",
            "type",
            "source",
            "reason",
            "reputation",
            "confidence",
            "first_observed",
            "investigation_id",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        # Prevent formula injection when analysts open exports in Excel.
        for row in rows:
            writer.writerow(
                {
                    k: "'" + str(row[k])
                    if str(row[k]).lstrip().startswith(("=", "+", "-", "@", "\t", "\r"))
                    else row[k]
                    for k in fields
                }
            )
        content = output.getvalue().encode("utf-8-sig")
    return Response(
        content,
        media_type="application/json" if format == "json" else "text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="phishscope-iocs.{format}"'
        },
    )


@app.post("/api/investigations/{case_id}/lookup")
def enrich(case_id: str, body: LookupInput, db: Session = Depends(get_db)):
    case = get_case(db, case_id)
    if case.simulation:
        raise HTTPException(
            422, "Simulation indicators are never submitted to external providers"
        )
    indicator = next(
        (i for i in latest(db, case_id).result["iocs"] if i["id"] == body.indicator_id),
        None,
    )
    if not indicator:
        raise HTTPException(404, "Indicator not found")
    cache = db.scalars(
        select(Intelligence)
        .where(
            Intelligence.investigation_id == case_id,
            Intelligence.provider == body.provider,
            Intelligence.indicator == indicator["value"],
        )
        .order_by(Intelligence.checked_at.desc())
    ).first()
    if (
        cache
        and cache.result["status"] == "ok"
        and datetime.fromisoformat(cache.checked_at)
        > datetime.now(timezone.utc) - timedelta(hours=6)
    ):
        return {**cache.result, "cached": True}
    recent_count = sum(
        datetime.fromisoformat(r.checked_at)
        > datetime.now(timezone.utc) - timedelta(minutes=1)
        for r in db.scalars(
            select(Intelligence).where(Intelligence.provider == body.provider)
        )
    )
    if recent_count >= 10:
        raise HTTPException(
            429, "Local lookup limit reached: 10 per provider per minute"
        )
    result = lookup(body.provider, indicator["value"], indicator["type"])
    db.add(
        Intelligence(
            investigation_id=case_id,
            provider=body.provider,
            indicator=indicator["value"],
            result=result,
        )
    )
    db.commit()
    return result


@app.get("/api/techniques")
def techniques():
    return TECHNIQUES


@app.get("/api/investigations/{case_id}/report")
def report_preview(case_id: str, db: Session = Depends(get_db)):
    record = detail(db, get_case(db, case_id))
    return {
        "markdown": reports.markdown(record, settings(db)),
        "sections": reports.sections(record, settings(db)),
        "settings": settings(db),
    }


@app.get("/api/investigations/{case_id}/report/{format}")
def export_report(
    case_id: str, format: Literal["pdf", "md", "json"], db: Session = Depends(get_db)
):
    record = detail(db, get_case(db, case_id))
    prefs = settings(db)
    content = (
        reports.pdf(record, prefs)
        if format == "pdf"
        else reports.markdown(record, prefs).encode()
        if format == "md"
        else json.dumps(
            {
                "report_version": "1.0.0",
                "generated_at": now(),
                "settings": prefs,
                "investigation": record,
                "sections": reports.sections(record, prefs),
            },
            ensure_ascii=False,
            indent=2,
        ).encode()
    )
    db.add(
        ReportExport(
            investigation_id=case_id,
            revision_id=record["revision_id"],
            format=format,
            content_sha256=hashlib.sha256(content).hexdigest(),
        )
    )
    db.commit()
    return Response(
        content,
        media_type={
            "pdf": "application/pdf",
            "md": "text/markdown",
            "json": "application/json",
        }[format],
        headers={
            "Content-Disposition": f'attachment; filename="phishscope-{case_id}.{format}"'
        },
    )


@app.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    providers = []
    for provider, env in PROVIDERS.items():
        last = db.scalars(
            select(Intelligence)
            .where(Intelligence.provider == provider)
            .order_by(Intelligence.checked_at.desc())
        ).first()
        providers.append(
            {
                "id": provider,
                "configured": bool(os.getenv(env)),
                "environment_variable": env,
                "last_status": last.result["status"] if last else "untested",
                "last_checked": last.checked_at if last else None,
            }
        )
    return {
        "preferences": settings(db),
        "providers": providers,
        "version": "1.0.0",
        "max_upload_mb": 5,
        "database": "SQLite" if str(engine.url).startswith("sqlite") else "PostgreSQL",
        "investigations": len(db.scalars(select(Investigation)).all()),
    }


@app.patch("/api/settings")
def update_settings(body: SettingsInput, db: Session = Depends(get_db)):
    stored = db.get(Setting, "preferences")
    if stored:
        stored.value = body.model_dump()
    else:
        db.add(Setting(key="preferences", value=body.model_dump()))
    db.commit()
    return get_settings(db)

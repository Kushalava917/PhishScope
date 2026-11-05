import os
import uuid
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import JSON, ForeignKey, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .analysis import now

load_dotenv()
Path("data").mkdir(exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/phishscope.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {},
)
if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def configure_sqlite(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")


SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def uid():
    return str(uuid.uuid4())


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    raw_email: Mapped[str] = mapped_column(Text)
    # base64 preserves the exact submitted bytes, including non-UTF8 source.
    original_base64: Mapped[str] = mapped_column(Text)
    evidence_sha256: Mapped[str] = mapped_column(String(64))
    simulation: Mapped[bool] = mapped_column(default=False)
    sample_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="completed")


class Revision(Base):
    __tablename__ = "analysis_revisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    result: Mapped[dict] = mapped_column(JSON)


class Indicator(Base):
    __tablename__ = "indicators"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    revision_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_revisions.id", ondelete="CASCADE"), index=True
    )
    value: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(String(20), index=True)
    detail: Mapped[dict] = mapped_column(JSON)


class Intelligence(Base):
    __tablename__ = "intelligence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(String(30))
    indicator: Mapped[str] = mapped_column(Text)
    checked_at: Mapped[str] = mapped_column(String(40), default=now)
    result: Mapped[dict] = mapped_column(JSON)


class ReportExport(Base):
    __tablename__ = "report_exports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    revision_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_revisions.id", ondelete="CASCADE")
    )
    format: Mapped[str] = mapped_column(String(10))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    content_sha256: Mapped[str] = mapped_column(String(64))


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


def get_db():
    with SessionLocal() as session:
        yield session

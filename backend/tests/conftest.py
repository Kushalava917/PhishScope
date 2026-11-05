import os
import tempfile
from pathlib import Path

import pytest

# The test database never shares the analyst workspace database.
TEST_DIR = tempfile.TemporaryDirectory(prefix="phishscope-tests-")
os.environ["DATABASE_URL"] = (
    "sqlite:///" + (Path(TEST_DIR.name) / "tests.db").as_posix()
)
from backend.db import Base, engine
from backend.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session", autouse=True)
def schema():
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")
    yield
    engine.dispose()
    TEST_DIR.cleanup()

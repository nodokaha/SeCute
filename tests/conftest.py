"""Shared test setup: make the harness and tracker importable and
provide a throwaway tracker database per test."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness"))
sys.path.insert(0, os.path.join(ROOT, "tracker"))


@pytest.fixture()
def db_path(tmp_path):
    from app import db
    path = str(tmp_path / "test.db")
    db.init_db(path)
    return path


@pytest.fixture()
def conn(db_path):
    from app import db
    c = db.connect(db_path)
    yield c
    c.close()

from __future__ import annotations

import pytest

from arpsurgeon.storage import Database


@pytest.fixture
def tmp_db(tmp_path):
    """Fresh SQLite database in a temp directory."""
    db_path = str(tmp_path / "test.db")
    return Database(db_path=db_path)


@pytest.fixture
def sample_host():
    return {
        "ip": "192.168.1.100",
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "test-host",
        "vendor": "TestVendor",
        "os": "Linux",
    }

"""Integration tests for arpsurgeon.web.api (FastAPI endpoints).

The engine adapters are replaced with fakes that just sleep until their
stop_event is set, so no real network operations are attempted.
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: patch Database to use a temp file *before* arpsurgeon.web.api
# is imported for the first time (its module-level code creates a Database).
# ---------------------------------------------------------------------------
_BOOTSTRAP_DB_DIR = tempfile.mkdtemp()
_BOOTSTRAP_DB_PATH = os.path.join(_BOOTSTRAP_DB_DIR, "bootstrap.db")

_orig_db_init = None

def _patched_db_init(self, db_path=None):
    """Use a temp database path when no explicit path is given."""
    if db_path is None:
        db_path = _BOOTSTRAP_DB_PATH
    _orig_db_init(self, db_path)


# Apply the patch before importing any arpsurgeon.web module
import arpsurgeon.storage
_orig_db_init = arpsurgeon.storage.Database.__init__
arpsurgeon.storage.Database.__init__ = _patched_db_init

# Now it's safe to import - module-level Database() will use the temp path
import arpsurgeon.engine
import arpsurgeon.web.api as api_module

# Restore original __init__
arpsurgeon.storage.Database.__init__ = _orig_db_init


def _fake_adapter(args, stop_event):
    """Stand-in adapter that blocks until told to stop."""
    while not stop_event.is_set():
        time.sleep(0.05)


_FAKE_ADAPTERS = {
    "monitor": _fake_adapter,
    "profile": _fake_adapter,
    "campaign": _fake_adapter,
}


@pytest.fixture(autouse=True)
def _patch_engine_and_db(tmp_path):
    """Patch JOB_ADAPTERS with fakes and give the API a temp database."""
    with patch.object(arpsurgeon.engine, "JOB_ADAPTERS", _FAKE_ADAPTERS):
        # Reset the manager's job list between tests
        from arpsurgeon.engine import manager
        with manager.lock:
            manager.jobs.clear()

        # Point the api module's Database to a temp file
        tmp_db = arpsurgeon.storage.Database(db_path=str(tmp_path / "api_test.db"))
        with patch.object(api_module, "db", tmp_db):
            yield


@pytest.fixture
def client():
    """Provide a Starlette TestClient wired to the FastAPI app."""
    from starlette.testclient import TestClient
    return TestClient(api_module.app)


# ---------- endpoint tests ----------

class TestRootEndpoint:
    def test_root_redirects(self, client):
        """GET / should redirect to the static UI."""
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 307
        assert "/static/index.html" in resp.headers.get("location", "")


class TestJobEndpoints:
    def test_list_jobs_empty(self, client):
        """Initially there should be no jobs."""
        resp = client.get("/api/v1/jobs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_start_job_invalid_type(self, client):
        """Starting an unknown job type should return 400."""
        resp = client.post("/api/v1/jobs/nonexistent", json={"args": {}})
        assert resp.status_code == 400

    def test_start_and_list_job(self, client):
        """Starting a monitor job should make it visible in the job list."""
        resp = client.post("/api/v1/jobs/monitor", json={"args": {}})
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data

        # Give the thread a moment to start
        time.sleep(0.15)

        jobs = client.get("/api/v1/jobs").json()
        assert len(jobs) >= 1
        job = next(j for j in jobs if j["job_id"] == data["job_id"])
        assert job["status"] == "running"

        # Cleanup: stop the job so the thread doesn't linger
        client.delete(f"/api/v1/jobs/{data['job_id']}")
        time.sleep(0.15)

    def test_stop_job(self, client):
        """Stopping a running job should change its status to 'stopped'."""
        resp = client.post("/api/v1/jobs/monitor", json={"args": {}})
        job_id = resp.json()["job_id"]
        time.sleep(0.15)

        stop_resp = client.delete(f"/api/v1/jobs/{job_id}")
        assert stop_resp.status_code == 200
        assert stop_resp.json()["status"] == "stopping"

        time.sleep(0.15)
        jobs = client.get("/api/v1/jobs").json()
        job = next(j for j in jobs if j["job_id"] == job_id)
        assert job["status"] in ("stopped", "completed")

    def test_stop_job_not_found(self, client):
        """Stopping a non-existent job should return 404."""
        resp = client.delete("/api/v1/jobs/does-not-exist")
        assert resp.status_code == 404


class TestHostEndpoints:
    def test_get_hosts_empty(self, client):
        """GET /api/v1/hosts on a fresh DB should return a paginated response with empty items."""
        resp = client.get("/api/v1/hosts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert "limit" in data
        assert "offset" in data

    def test_clear_hosts(self, client):
        """DELETE /api/v1/hosts should return a 'cleared' status."""
        resp = client.delete("/api/v1/hosts")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cleared"


class TestEventEndpoints:
    def test_get_events(self, client):
        """GET /api/v1/events should return a paginated response (empty initially)."""
        resp = client.get("/api/v1/events")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["items"], list)
        assert data["total"] == 0


class TestProfileEndpoints:
    def test_get_profiles_structure(self, client):
        """GET /api/v1/profiles should return a dict with the expected top-level keys."""
        resp = client.get("/api/v1/profiles")
        assert resp.status_code == 200
        data = resp.json()
        expected_keys = {
            "monitor", "profile", "campaign", "discover",
            "poison", "mitm", "sever", "fuzz", "dns-spoof",
        }
        assert expected_keys.issubset(set(data.keys()))


class TestStatsEndpoint:
    def test_get_stats(self, client):
        """GET /api/v1/stats should return stats with expected keys."""
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "hosts" in data
        assert "events" in data
        assert "active_jobs" in data
        assert "uptime_seconds" in data
        assert data["hosts"] == 0
        assert data["events"] == 0


class TestGetJobEndpoint:
    def test_get_job_found(self, client):
        """GET /api/v1/jobs/{id} for an existing job should return its details."""
        resp = client.post("/api/v1/jobs/monitor", json={"args": {}})
        job_id = resp.json()["job_id"]
        time.sleep(0.15)

        resp = client.get(f"/api/v1/jobs/{job_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == job_id
        assert data["type"] == "monitor"

        # Cleanup
        client.delete(f"/api/v1/jobs/{job_id}")
        time.sleep(0.15)

    def test_get_job_not_found(self, client):
        """GET /api/v1/jobs/{id} for a missing job should return 404."""
        resp = client.get("/api/v1/jobs/nope")
        assert resp.status_code == 404


class TestClearEventsEndpoint:
    def test_clear_events(self, client):
        """DELETE /api/v1/events should return a 'cleared' status."""
        resp = client.delete("/api/v1/events")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cleared"


class TestExportEndpoints:
    def test_export_hosts_csv(self, client):
        """GET /api/v1/hosts/export?format=csv should return CSV content."""
        resp = client.get("/api/v1/hosts/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")

    def test_export_hosts_json(self, client):
        """GET /api/v1/hosts/export?format=json should return a JSON list."""
        resp = client.get("/api/v1/hosts/export?format=json")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_export_events_csv(self, client):
        """GET /api/v1/events/export?format=csv should return CSV content."""
        resp = client.get("/api/v1/events/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")

    def test_export_events_json(self, client):
        """GET /api/v1/events/export?format=json should return a JSON list."""
        resp = client.get("/api/v1/events/export?format=json")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestTopologyEndpoint:
    def test_topology_empty(self, client):
        """GET /api/v1/topology on empty DB should return empty nodes and edges."""
        resp = client.get("/api/v1/topology")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data
        assert data["nodes"] == []
        assert data["edges"] == []

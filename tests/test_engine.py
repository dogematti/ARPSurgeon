"""Tests for arpsurgeon.engine (Job, JobManager, adapter registry)."""
from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from arpsurgeon.engine import Job, JobManager, JOB_ADAPTERS


def _fake_adapter(args, stop_event):
    """Stand-in adapter that blocks until told to stop."""
    while not stop_event.is_set():
        time.sleep(0.02)


def _fast_adapter(args, stop_event):
    """Adapter that completes immediately."""
    pass


def _failing_adapter(args, stop_event):
    """Adapter that always raises."""
    raise ValueError("simulated failure")


_TEST_ADAPTERS = {
    "fake": _fake_adapter,
    "fast": _fast_adapter,
    "fail": _failing_adapter,
}


@pytest.fixture(autouse=True)
def _use_test_adapters():
    with patch.object(
        __import__("arpsurgeon.engine", fromlist=["JOB_ADAPTERS"]),
        "JOB_ADAPTERS",
        _TEST_ADAPTERS,
    ):
        yield


class TestJob:
    def test_job_initial_state(self):
        job = Job("abc", "fake", {"key": "val"})
        assert job.id == "abc"
        assert job.type == "fake"
        assert job.status == "pending"
        assert job.start_time == 0.0
        assert job.end_time is None
        assert job.error is None

    def test_job_duration_before_start(self):
        job = Job("abc", "fake", {})
        assert job.duration is None

    def test_job_completes(self):
        job = Job("abc", "fast", {})
        job.run()
        assert job.status == "completed"
        assert job.end_time is not None
        assert job.duration is not None
        assert job.duration >= 0

    def test_job_fails(self):
        job = Job("abc", "fail", {})
        job.run()
        assert job.status == "failed"
        assert "simulated failure" in job.error
        assert job.end_time is not None

    def test_job_unknown_type(self):
        job = Job("abc", "nonexistent", {})
        job.run()
        assert job.status == "failed"
        assert "Unknown job type" in job.error

    def test_job_stop(self):
        job = Job("abc", "fake", {})
        t = threading.Thread(target=job.run, daemon=True)
        t.start()
        time.sleep(0.05)
        assert job.status == "running"
        job.stop()
        t.join(timeout=1)
        assert job.status == "completed"


class TestJobManager:
    def test_start_job(self):
        mgr = JobManager()
        job_id = mgr.start_job("fast", {})
        assert len(job_id) == 8
        time.sleep(0.1)
        jobs = mgr.list_jobs()
        assert len(jobs) == 1
        assert jobs[0].status == "completed"

    def test_start_invalid_type(self):
        mgr = JobManager()
        with pytest.raises(ValueError, match="Invalid job type"):
            mgr.start_job("nonexistent", {})

    def test_stop_job(self):
        mgr = JobManager()
        job_id = mgr.start_job("fake", {})
        time.sleep(0.05)
        assert mgr.stop_job(job_id) is True
        time.sleep(0.1)
        job = mgr.get_job(job_id)
        assert job.status in ("stopped", "completed")

    def test_stop_nonexistent(self):
        mgr = JobManager()
        assert mgr.stop_job("nope") is False

    def test_get_job(self):
        mgr = JobManager()
        job_id = mgr.start_job("fast", {"x": 1})
        time.sleep(0.1)
        job = mgr.get_job(job_id)
        assert job is not None
        assert job.job_id == job_id
        assert job.type == "fast"
        assert job.args == {"x": 1}

    def test_get_job_nonexistent(self):
        mgr = JobManager()
        assert mgr.get_job("nope") is None

    def test_list_jobs_multiple(self):
        mgr = JobManager()
        mgr.start_job("fast", {})
        mgr.start_job("fast", {})
        time.sleep(0.1)
        jobs = mgr.list_jobs()
        assert len(jobs) == 2

    def test_cleanup_old_jobs(self):
        mgr = JobManager()
        job_id = mgr.start_job("fast", {})
        time.sleep(0.1)

        # Manually set end_time far in the past
        with mgr.lock:
            mgr.jobs[job_id].end_time = time.time() - 7200  # 2 hours ago

        # Starting a new job triggers cleanup
        mgr.start_job("fast", {})
        time.sleep(0.1)
        # The old job should have been cleaned up
        assert mgr.get_job(job_id) is None

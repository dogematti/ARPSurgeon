from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class Host(BaseModel):
    ip: str
    mac: str = "unknown"
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    first_seen: float
    last_seen: float
    count: int = 1


class EventLog(BaseModel):
    id: Optional[int] = None
    timestamp: float
    type: str
    data: Dict[str, Any]


class JobStatus(BaseModel):
    job_id: str
    type: str
    status: str  # "running", "stopped", "failed", "completed"
    start_time: float
    end_time: Optional[float] = None
    error: Optional[str] = None
    args: Dict[str, Any] = Field(default_factory=dict)

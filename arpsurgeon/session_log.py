from __future__ import annotations

import json
import os
import time
from typing import Optional

from scapy.utils import PcapWriter  # type: ignore


class JsonlLogger:
    def __init__(self, path: Optional[str]) -> None:
        self._path = path
        self._handle = open(path, "a", encoding="ascii") if path else None

    def log(self, payload: dict) -> None:
        if not self._handle:
            return
        self._handle.write(json.dumps(payload, ensure_ascii=True))
        self._handle.write("\n")
        self._handle.flush()

    def close(self) -> None:
        if self._handle:
            self._handle.close()


class PcapLogger:
    def __init__(
        self,
        path: Optional[str],
        max_bytes: Optional[int] = None,
        max_seconds: Optional[int] = None,
    ) -> None:
        self._path = path
        self._max_bytes = max_bytes if max_bytes and max_bytes > 0 else None
        self._max_seconds = max_seconds if max_seconds and max_seconds > 0 else None
        self._index = 0
        self._start = time.monotonic()
        self._writer = None
        self._current_path = None
        if path:
            self._open_writer()

    def _open_writer(self) -> None:
        if not self._path:
            return
        path = self._path
        if self._max_bytes or self._max_seconds:
            base, ext = os.path.splitext(path)
            ext = ext or ".pcap"
            path = f"{base}.{self._index:04d}{ext}"
        self._current_path = path
        self._writer = PcapWriter(path, append=True, sync=True)
        self._start = time.monotonic()

    def _rotate_if_needed(self) -> None:
        if not self._writer or not self._current_path:
            return
        if self._max_seconds and (time.monotonic() - self._start) >= self._max_seconds:
            self._rotate()
            return
        if self._max_bytes and os.path.exists(self._current_path):
            if os.path.getsize(self._current_path) >= self._max_bytes:
                self._rotate()

    def _rotate(self) -> None:
        if self._writer:
            self._writer.close()
        self._index += 1
        self._open_writer()

    def write(self, pkt) -> None:
        if not self._writer:
            return
        self._rotate_if_needed()
        if self._writer:
            self._writer.write(pkt)

    def close(self) -> None:
        if self._writer:
            self._writer.close()

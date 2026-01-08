from __future__ import annotations

import curses
import json
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict


ALERT_TYPES = {"conflict", "storm", "gratuitous"}


def run_dashboard(path: str, refresh: float, max_events: int) -> None:
    file_path = Path(path)
    if not file_path.exists():
        raise SystemExit(f"jsonl file not found: {path}")

    def _main(stdscr) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        if curses.LINES < 10 or curses.COLS < 40:
             stdscr.addstr(0, 0, "Terminal too small (need 10x40)")
             stdscr.refresh()
             time.sleep(2)
             return

        counts: Dict[str, int] = {}
        events: Deque[dict] = deque(maxlen=max_events)
        offset = 0

        while True:
            try:
                with file_path.open("r", encoding="ascii", errors="ignore") as handle:
                    handle.seek(offset)
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        etype = event.get("type", "unknown")
                        counts[etype] = counts.get(etype, 0) + 1
                        events.append(event)
                    offset = handle.tell()
            except FileNotFoundError:
                pass

            stdscr.erase()
            try:
                stdscr.addstr(0, 0, "ARPSurgeon Dashboard")
                stdscr.addstr(1, 0, f"File: {path}")
                stdscr.addstr(2, 0, f"Updated: {time.strftime('%H:%M:%S')}")

                if curses.LINES > 5:
                    stdscr.addstr(4, 0, "Counts")
                    row = 5
                    for etype, count in sorted(counts.items()):
                        if row >= curses.LINES - 2:
                            break
                        stdscr.addstr(row, 2, f"{etype:<16} {count}")
                        row += 1

                    row += 1
                    if row < curses.LINES - 2:
                        stdscr.addstr(row, 0, "Recent Events")
                        row += 1
                        for event in list(events)[-max_events:]:
                            if row >= curses.LINES - 2:
                                break
                            etype = event.get("type", "unknown")
                            line = f"{etype:<12} {event.get('src_ip',''):>15} -> {event.get('dst_ip',''):<15} {event.get('qname','')}"
                            if etype in ALERT_TYPES:
                                stdscr.addstr(row, 2, line[: curses.COLS - 3], curses.A_BOLD)
                            else:
                                stdscr.addstr(row, 2, line[: curses.COLS - 3])
                            row += 1

                stdscr.addstr(curses.LINES - 1, 0, "Press q to quit")
            except curses.error:
                pass
            stdscr.refresh()

            try:
                key = stdscr.getkey()
            except curses.error:
                key = None
            if key in {"q", "Q"}:
                break
            time.sleep(refresh)

    curses.wrapper(_main)

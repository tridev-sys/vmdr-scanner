"""Run an external command in its own process group, with heartbeats, a deadline, and interruption.

Why a process group: Nuclei may spawn helpers, and a shutdown has to stop all of them.
Why the stop event: the worker's SIGTERM handler only sets an event. Without this loop checking
it, a multi-hour scan keeps running until the supervisor SIGKILLs the whole worker.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)
HEARTBEAT_INTERVAL_S = 15
TERM_GRACE_S = 10


@dataclass
class ProcessOutcome:
    returncode: int | None
    timed_out: bool = False
    interrupted: bool = False


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


def terminate_group(proc: subprocess.Popen) -> None:
    """SIGTERM the process group, then SIGKILL it if it has not exited after TERM_GRACE_S."""
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=TERM_GRACE_S)
    except subprocess.TimeoutExpired:
        _signal_group(proc, signal.SIGKILL)
        proc.wait()


def run_process(
    cmd: list[str],
    log_path: Path,
    timeout_s: int,
    stop_event: threading.Event,
    on_heartbeat: Callable[[], None] | None = None,
    pid_path: Path | None = None,
) -> ProcessOutcome:
    """Run `cmd`, writing stdout+stderr to `log_path`. Raises FileNotFoundError if the binary is missing."""
    with log_path.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
    if pid_path is not None:
        pid_path.write_text(str(proc.pid), encoding="utf-8")
    deadline = time.monotonic() + timeout_s
    try:
        while True:
            try:
                returncode = proc.wait(timeout=HEARTBEAT_INTERVAL_S)
                return ProcessOutcome(returncode)
            except subprocess.TimeoutExpired:
                pass
            if stop_event.is_set():
                logger.warning("shutdown requested; terminating pid %s", proc.pid)
                terminate_group(proc)
                return ProcessOutcome(proc.returncode, interrupted=True)
            if time.monotonic() >= deadline:
                terminate_group(proc)
                return ProcessOutcome(proc.returncode, timed_out=True)
            if on_heartbeat is not None:
                on_heartbeat()
    finally:
        if pid_path is not None:
            pid_path.unlink(missing_ok=True)
        if proc.poll() is None:  # never leave a process behind if this function raised
            terminate_group(proc)


def kill_stale_group(pid_path: Path) -> bool:
    """Kill the process group recorded by a previous worker that died without cleaning up."""
    if not pid_path.exists():
        return False
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
        os.killpg(pid, signal.SIGKILL)
        killed = True
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        killed = False
    pid_path.unlink(missing_ok=True)
    return killed

"""Safe execution runner for target binaries and Valgrind instrumentation."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Mapping, Optional

from .models import RunResult


def _normalize_input_bytes(stdin_data: Optional[str | bytes]) -> Optional[bytes]:
    """Normalize optional stdin payload into bytes for subprocess I/O."""
    if stdin_data is None:
        return None
    if isinstance(stdin_data, bytes):
        return stdin_data
    return stdin_data.encode("utf-8", errors="replace")


def _read_limited(tmp_file, max_bytes: int) -> tuple[str, bool]:
    """
    Read from a temp output file with a strict byte cap.

    We intentionally store process output in temporary files (not memory pipes),
    then load at most `max_bytes` for reporting to avoid memory pressure in CI.
    """
    tmp_file.flush()
    tmp_file.seek(0, os.SEEK_END)
    total_size = tmp_file.tell()
    truncated = total_size > max_bytes
    tmp_file.seek(0)

    data = tmp_file.read(max_bytes if truncated else total_size)
    text = data.decode("utf-8", errors="replace")
    return text, truncated


def _signal_name_from_return_code(return_code: Optional[int]) -> Optional[str]:
    """Translate negative return codes into human-readable POSIX signal names."""
    if return_code is None or return_code >= 0:
        return None
    sig_num = -return_code
    try:
        return signal.Signals(sig_num).name
    except ValueError:
        return f"SIG{sig_num}"


def _terminate_process_group(process: subprocess.Popen, kill_grace_seconds: float) -> None:
    """
    Best-effort process tree cleanup.

    The process is started as a new session (`start_new_session=True`) so its PID
    can be used as a process group ID and terminated in one call.
    """
    if process.poll() is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=kill_grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait()


def _validate_binary_path(binary_path: str) -> Path:
    """Resolve and validate that the target path points to an executable file."""
    resolved = Path(binary_path).expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Target binary does not exist: {resolved}")
    if not resolved.is_file():
        raise ValueError(f"Target path is not a regular file: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise PermissionError(f"Target file is not executable: {resolved}")
    return resolved


def build_execution_command(
    binary_path: str,
    args: Optional[list[str]] = None,
    use_valgrind: bool = False,
    valgrind_log_path: Optional[str] = None,
    extra_valgrind_args: Optional[list[str]] = None,
) -> tuple[list[str], Optional[str]]:
    """
    Construct a safe argv list for execution.

    No shell expansion is used. Every token is passed as an explicit argv item.
    """
    target = _validate_binary_path(binary_path)
    argv = [str(target), *(args or [])]

    if not use_valgrind:
        return argv, None

    if shutil.which("valgrind") is None:
        raise FileNotFoundError("`valgrind` is not installed or not found in PATH.")

    resolved_log_path: Optional[str] = None
    if valgrind_log_path:
        resolved_log_path = str(Path(valgrind_log_path).expanduser().resolve())
        Path(resolved_log_path).parent.mkdir(parents=True, exist_ok=True)

    if not resolved_log_path:
        fd, temp_path = tempfile.mkstemp(prefix="aegis-valgrind-", suffix=".log")
        os.close(fd)
        resolved_log_path = temp_path

    valgrind_base = [
        "valgrind",
        "--tool=memcheck",
        "--leak-check=full",
        "--show-leak-kinds=all",
        "--track-fds=yes",
        f"--log-file={resolved_log_path}",
    ]

    if extra_valgrind_args:
        valgrind_base.extend(extra_valgrind_args)

    return [*valgrind_base, *argv], resolved_log_path


def run_binary(
    binary_path: str,
    args: Optional[list[str]] = None,
    stdin_data: Optional[str | bytes] = None,
    timeout_seconds: int = 30,
    cwd: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    use_valgrind: bool = False,
    valgrind_log_path: Optional[str] = None,
    extra_valgrind_args: Optional[list[str]] = None,
    kill_grace_seconds: float = 2.0,
    max_output_bytes: int = 4 * 1024 * 1024,
) -> RunResult:
    """
    Execute a target binary under monitored conditions.

    Safety properties:
    - `shell=False` to avoid shell injection.
    - Explicit argv list.
    - New process session for process-tree termination on timeout.
    - Optional timeout handling to protect CI from infinite loops.
    """
    start = time.monotonic()
    input_bytes = _normalize_input_bytes(stdin_data)

    try:
        command, resolved_vg_log = build_execution_command(
            binary_path=binary_path,
            args=args,
            use_valgrind=use_valgrind,
            valgrind_log_path=valgrind_log_path,
            extra_valgrind_args=extra_valgrind_args,
        )
    except Exception as exc:  # noqa: BLE001 - return structured error to caller.
        return RunResult(
            command=[],
            exit_code=None,
            stdout="",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
            duration_seconds=time.monotonic() - start,
            termination_reason="spawn_error",
            signal_name=None,
            valgrind_log_path=None,
            error=str(exc),
        )

    child_env = dict(os.environ)
    if env:
        child_env.update(env)

    # Temporary files avoid unbounded in-memory output accumulation.
    with tempfile.TemporaryFile() as stdout_tmp, tempfile.TemporaryFile() as stderr_tmp:
        process: Optional[subprocess.Popen] = None
        timed_out = False

        try:
            process = subprocess.Popen(
                command,
                shell=False,
                stdin=subprocess.PIPE if input_bytes is not None else None,
                stdout=stdout_tmp,
                stderr=stderr_tmp,
                cwd=cwd,
                env=child_env,
                start_new_session=True,
                close_fds=True,
            )

            process.communicate(input=input_bytes, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            if process is not None:
                _terminate_process_group(process, kill_grace_seconds=kill_grace_seconds)
        except Exception as exc:  # noqa: BLE001 - keep CLI flow alive with details.
            return RunResult(
                command=command,
                exit_code=None,
                stdout="",
                stderr="",
                stdout_truncated=False,
                stderr_truncated=False,
                timed_out=False,
                duration_seconds=time.monotonic() - start,
                termination_reason="spawn_error",
                signal_name=None,
                valgrind_log_path=resolved_vg_log,
                error=str(exc),
            )

        stdout_text, stdout_truncated = _read_limited(stdout_tmp, max_output_bytes=max_output_bytes)
        stderr_text, stderr_truncated = _read_limited(stderr_tmp, max_output_bytes=max_output_bytes)

    exit_code = process.returncode if process is not None else None
    signal_name = _signal_name_from_return_code(exit_code)

    if timed_out:
        termination_reason = "timeout"
    elif signal_name:
        termination_reason = f"signal:{signal_name}"
    else:
        termination_reason = "exited"

    return RunResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout_text,
        stderr=stderr_text,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        timed_out=timed_out,
        duration_seconds=time.monotonic() - start,
        termination_reason=termination_reason,
        signal_name=signal_name,
        valgrind_log_path=resolved_vg_log,
        error=None,
    )

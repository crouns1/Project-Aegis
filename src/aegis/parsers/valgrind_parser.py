"""Valgrind log parser for memory and file-descriptor leak findings."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import ValgrindFindings

# Core leak summary lines.
DEFINITELY_LOST_RE = re.compile(
    r"==\d+==\s+definitely lost:\s+([0-9,]+)\s+bytes in\s+([0-9,]+)\s+blocks",
    re.IGNORECASE,
)
INDIRECTLY_LOST_RE = re.compile(
    r"==\d+==\s+indirectly lost:\s+([0-9,]+)\s+bytes in\s+([0-9,]+)\s+blocks",
    re.IGNORECASE,
)

# Invalid memory access events.
INVALID_READ_RE = re.compile(r"==\d+==\s+Invalid read of size\s+\d+", re.IGNORECASE)
INVALID_WRITE_RE = re.compile(r"==\d+==\s+Invalid write of size\s+\d+", re.IGNORECASE)

# FD tracking summary and verbose lines.
FD_SUMMARY_RE = re.compile(
    r"==\d+==\s+FILE DESCRIPTORS:\s+([0-9,]+)\s+open(?:\s+\(([0-9,]+)\s+std\))?\s+at exit",
    re.IGNORECASE,
)
OPEN_FD_LINE_RE = re.compile(
    r"==\d+==\s+Open file descriptor\s+([0-9]+):",
    re.IGNORECASE,
)

# Global error summary.
ERROR_SUMMARY_RE = re.compile(
    r"==\d+==\s+ERROR SUMMARY:\s+([0-9,]+)\s+errors from\s+([0-9,]+)\s+contexts",
    re.IGNORECASE,
)


def _to_int(number_text: str) -> int:
    """Convert Valgrind-formatted numbers (with commas) to int."""
    return int(number_text.replace(",", "").strip())


def parse_valgrind_trace(trace_text: str, raw_trace_path: str | None = None) -> ValgrindFindings:
    """
    Parse raw Valgrind trace text into structured findings.

    The parser is intentionally strict and deterministic so CI behavior remains
    stable regardless of model usage.
    """
    findings = ValgrindFindings(raw_trace_path=raw_trace_path)

    definitely_match = DEFINITELY_LOST_RE.search(trace_text)
    if definitely_match:
        findings.definitely_lost_bytes = _to_int(definitely_match.group(1))
        findings.definitely_lost_blocks = _to_int(definitely_match.group(2))

    indirectly_match = INDIRECTLY_LOST_RE.search(trace_text)
    if indirectly_match:
        findings.indirectly_lost_bytes = _to_int(indirectly_match.group(1))
        findings.indirectly_lost_blocks = _to_int(indirectly_match.group(2))

    findings.invalid_read_events = len(INVALID_READ_RE.findall(trace_text))
    findings.invalid_write_events = len(INVALID_WRITE_RE.findall(trace_text))
    findings.total_invalid_access_events = findings.invalid_read_events + findings.invalid_write_events

    # Primary FD source: Valgrind summary line.
    fd_summary_match = FD_SUMMARY_RE.search(trace_text)
    if fd_summary_match:
        findings.open_fds_at_exit = _to_int(fd_summary_match.group(1))
        findings.std_fds_at_exit = _to_int(fd_summary_match.group(2)) if fd_summary_match.group(2) else 3
        findings.unclosed_fds = max(findings.open_fds_at_exit - findings.std_fds_at_exit, 0)
    else:
        # Fallback path for logs where summary is absent but detailed lines exist.
        fds = {int(fd) for fd in OPEN_FD_LINE_RE.findall(trace_text)}
        findings.open_fds_at_exit = len(fds)
        findings.std_fds_at_exit = len({fd for fd in fds if fd in (0, 1, 2)})
        findings.unclosed_fds = len({fd for fd in fds if fd > 2})

    error_summary_match = ERROR_SUMMARY_RE.search(trace_text)
    if error_summary_match:
        findings.error_summary_total = _to_int(error_summary_match.group(1))
        findings.error_summary_contexts = _to_int(error_summary_match.group(2))

    return findings


def parse_valgrind_trace_file(trace_path: str) -> ValgrindFindings:
    """Load and parse a Valgrind trace file from disk."""
    resolved = Path(trace_path).expanduser().resolve()
    text = resolved.read_text(encoding="utf-8", errors="replace")
    return parse_valgrind_trace(text, raw_trace_path=str(resolved))

"""Shared typed models for Aegis modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class RunResult:
    """Result of a monitored process execution."""

    command: list[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    duration_seconds: float
    termination_reason: str
    signal_name: Optional[str]
    valgrind_log_path: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValgrindFindings:
    """Structured findings extracted from Valgrind output."""

    definitely_lost_bytes: int = 0
    definitely_lost_blocks: int = 0
    indirectly_lost_bytes: int = 0
    indirectly_lost_blocks: int = 0
    invalid_read_events: int = 0
    invalid_write_events: int = 0
    total_invalid_access_events: int = 0
    open_fds_at_exit: int = 0
    std_fds_at_exit: int = 3
    unclosed_fds: int = 0
    error_summary_total: int = 0
    error_summary_contexts: int = 0
    raw_trace_path: Optional[str] = None

    def has_actionable_issues(self) -> bool:
        return any(
            [
                self.definitely_lost_bytes > 0,
                self.indirectly_lost_bytes > 0,
                self.total_invalid_access_events > 0,
                self.unclosed_fds > 0,
            ]
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OllamaAnalysisResult:
    """Result of a local Ollama analysis request."""

    model: str
    endpoint: str
    prompt: str
    raw_response_text: str
    structured_response: Optional[Dict[str, Any]]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

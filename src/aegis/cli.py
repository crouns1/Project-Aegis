"""Command-line interface for Project Aegis Phase 1 MVP."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .ai.ollama_client import query_ollama_root_cause
from .models import OllamaAnalysisResult, RunResult, ValgrindFindings
from .parsers.valgrind_parser import parse_valgrind_trace_file
from .runner import run_binary


def _read_source_snippet(path: Optional[str], line_start: int, line_end: int) -> str:
    """Load a bounded source snippet for AI analysis context."""
    if not path:
        return ""
    resolved = Path(path).expanduser().resolve()
    text = resolved.read_text(encoding="utf-8", errors="replace").splitlines()

    if not text:
        return ""

    start_index = max(line_start - 1, 0)
    end_index = min(line_end, len(text))
    if start_index >= end_index:
        return ""

    # Prefix lines with line numbers to preserve debugging context.
    numbered = [
        f"{i + 1:>6}: {line}"
        for i, line in enumerate(text[start_index:end_index], start=start_index)
    ]
    return "\n".join(numbered)


def _read_trace_excerpt(path: Optional[str], max_lines: int = 220) -> str:
    """Read the tail of a trace file to keep prompt size predictable."""
    if not path:
        return ""
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        return ""

    lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def _build_sarif_report(
    run_result: RunResult,
    findings: Optional[ValgrindFindings],
    source_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a minimal SARIF report consumable by CI systems.

    SARIF schema is intentionally simple here; Phase 2 can enrich with stack
    frames and precise source locations from debug symbols.
    """
    results: list[Dict[str, Any]] = []

    def _location() -> list[Dict[str, Any]]:
        if not source_path:
            return []
        return [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(Path(source_path).expanduser())}
                }
            }
        ]

    if findings:
        if findings.definitely_lost_bytes > 0:
            results.append(
                {
                    "ruleId": "AEGIS-MEM-DEF-LOST",
                    "level": "error",
                    "message": {
                        "text": f"Definitely lost memory detected: {findings.definitely_lost_bytes} bytes."
                    },
                    "locations": _location(),
                }
            )
        if findings.indirectly_lost_bytes > 0:
            results.append(
                {
                    "ruleId": "AEGIS-MEM-IND-LOST",
                    "level": "warning",
                    "message": {
                        "text": f"Indirectly lost memory detected: {findings.indirectly_lost_bytes} bytes."
                    },
                    "locations": _location(),
                }
            )
        if findings.total_invalid_access_events > 0:
            results.append(
                {
                    "ruleId": "AEGIS-MEM-INVALID-ACCESS",
                    "level": "error",
                    "message": {
                        "text": (
                            "Invalid memory access events detected: "
                            f"{findings.total_invalid_access_events}."
                        )
                    },
                    "locations": _location(),
                }
            )
        if findings.unclosed_fds > 0:
            results.append(
                {
                    "ruleId": "AEGIS-FD-LEAK",
                    "level": "warning",
                    "message": {
                        "text": f"Unclosed file descriptors detected: {findings.unclosed_fds}."
                    },
                    "locations": _location(),
                }
            )

    if run_result.timed_out:
        results.append(
            {
                "ruleId": "AEGIS-RUN-TIMEOUT",
                "level": "error",
                "message": {"text": "Target process exceeded timeout and was terminated."},
                "locations": _location(),
            }
        )
    elif run_result.signal_name:
        results.append(
            {
                "ruleId": "AEGIS-RUN-SIGNAL",
                "level": "error",
                "message": {"text": f"Target process terminated by signal {run_result.signal_name}."},
                "locations": _location(),
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Project Aegis",
                        "informationUri": "https://example.local/project-aegis",
                        "rules": [],
                    }
                },
                "results": results,
            }
        ],
    }


def _render_terminal(
    run_result: RunResult,
    findings: Optional[ValgrindFindings],
    ai_result: Optional[OllamaAnalysisResult],
) -> str:
    """Build a human-readable terminal report."""
    lines = []
    lines.append("== Aegis Run Summary ==")
    lines.append(f"Command: {' '.join(run_result.command)}")
    lines.append(f"Exit code: {run_result.exit_code}")
    lines.append(f"Termination: {run_result.termination_reason}")
    lines.append(f"Timed out: {run_result.timed_out}")
    lines.append(f"Duration: {run_result.duration_seconds:.3f}s")
    lines.append(f"Valgrind log: {run_result.valgrind_log_path or 'n/a'}")
    if run_result.error:
        lines.append(f"Runner error: {run_result.error}")

    if findings is not None:
        lines.append("")
        lines.append("== Valgrind Findings ==")
        lines.append(
            "Memory: "
            f"definitely_lost={findings.definitely_lost_bytes} bytes, "
            f"indirectly_lost={findings.indirectly_lost_bytes} bytes"
        )
        lines.append(
            "Invalid access events: "
            f"reads={findings.invalid_read_events}, writes={findings.invalid_write_events}, "
            f"total={findings.total_invalid_access_events}"
        )
        lines.append(
            "File descriptors: "
            f"open_at_exit={findings.open_fds_at_exit}, "
            f"std={findings.std_fds_at_exit}, "
            f"unclosed={findings.unclosed_fds}"
        )

    if ai_result is not None:
        lines.append("")
        lines.append("== Ollama Analysis ==")
        if ai_result.error:
            lines.append(f"AI error: {ai_result.error}")
        elif ai_result.structured_response is not None:
            lines.append(json.dumps(ai_result.structured_response, indent=2))
        else:
            lines.append(ai_result.raw_response_text)

    return "\n".join(lines)


def _read_stdin_payload(stdin_file: Optional[str], stdin_text: Optional[str]) -> Optional[str]:
    """Load optional stdin payload for the target process."""
    if stdin_file and stdin_text:
        raise ValueError("Use only one of --stdin-file or --stdin-text.")
    if stdin_text is not None:
        return stdin_text
    if stdin_file is not None:
        return Path(stdin_file).expanduser().resolve().read_text(encoding="utf-8", errors="replace")
    return None


def _determine_exit_code(run_result: RunResult, findings: Optional[ValgrindFindings]) -> int:
    """Map run outcomes to CI-friendly process exit codes."""
    if run_result.error:
        return 1
    if run_result.timed_out:
        return 124
    if findings and findings.has_actionable_issues():
        # Distinct non-zero code for detected defects.
        return 2
    if run_result.exit_code is None:
        return 1
    if run_result.exit_code < 0:
        # Mirror common POSIX convention for signal exits in shells.
        return 128 + abs(int(run_result.exit_code))
    return int(run_result.exit_code)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Project Aegis Phase 1 MVP CLI")
    parser.add_argument("--binary", required=True, help="Path to compiled target binary.")
    parser.add_argument("--arg", action="append", default=[], help="Argument passed to target binary.")
    parser.add_argument("--stdin-file", help="Optional path to stdin payload file.")
    parser.add_argument("--stdin-text", help="Optional inline stdin payload.")
    parser.add_argument("--timeout", type=int, default=30, help="Execution timeout in seconds.")
    parser.add_argument("--cwd", help="Optional working directory for target execution.")
    parser.add_argument("--valgrind", action="store_true", help="Run the target under Valgrind memcheck.")
    parser.add_argument("--valgrind-log", help="Optional explicit path for Valgrind log output.")
    parser.add_argument(
        "--valgrind-arg",
        action="append",
        default=[],
        help="Extra Valgrind argument. May be passed multiple times.",
    )
    parser.add_argument(
        "--output",
        choices=["terminal", "json", "sarif"],
        default="terminal",
        help="Select output format for local dev or CI ingestion.",
    )
    parser.add_argument("--max-output-bytes", type=int, default=4 * 1024 * 1024)

    # Optional AI analysis flags.
    parser.add_argument("--source", help="Optional C/C++ source file to include in AI context.")
    parser.add_argument("--line-start", type=int, default=1)
    parser.add_argument("--line-end", type=int, default=200)
    parser.add_argument("--ollama-model", help="Optional local Ollama model for root-cause analysis.")
    parser.add_argument("--ollama-endpoint", default="http://localhost:11434")
    parser.add_argument("--ollama-timeout", type=int, default=45)

    args = parser.parse_args(argv)

    try:
        stdin_payload = _read_stdin_payload(args.stdin_file, args.stdin_text)
    except Exception as exc:  # noqa: BLE001
        print(f"Input error: {exc}", file=sys.stderr)
        return 1

    run_result = run_binary(
        binary_path=args.binary,
        args=args.arg,
        stdin_data=stdin_payload,
        timeout_seconds=args.timeout,
        cwd=args.cwd,
        use_valgrind=args.valgrind,
        valgrind_log_path=args.valgrind_log,
        extra_valgrind_args=args.valgrind_arg,
        max_output_bytes=args.max_output_bytes,
    )

    findings: Optional[ValgrindFindings] = None
    if args.valgrind and run_result.valgrind_log_path:
        vg_log = Path(run_result.valgrind_log_path)
        if vg_log.exists():
            findings = parse_valgrind_trace_file(str(vg_log))

    ai_result: Optional[OllamaAnalysisResult] = None
    if args.ollama_model and findings and findings.has_actionable_issues():
        source_snippet = _read_source_snippet(args.source, args.line_start, args.line_end)
        trace_snippet = _read_trace_excerpt(run_result.valgrind_log_path)
        ai_result = query_ollama_root_cause(
            findings=findings,
            source_snippet=source_snippet,
            trace_snippet=trace_snippet,
            model=args.ollama_model,
            endpoint=args.ollama_endpoint,
            timeout_seconds=args.ollama_timeout,
        )

    output_payload: Dict[str, Any] = {
        "run": run_result.to_dict(),
        "findings": findings.to_dict() if findings else None,
        "ai": ai_result.to_dict() if ai_result else None,
    }

    if args.output == "terminal":
        print(_render_terminal(run_result, findings, ai_result))
    elif args.output == "json":
        print(json.dumps(output_payload, indent=2))
    else:
        print(json.dumps(_build_sarif_report(run_result, findings, source_path=args.source), indent=2))

    return _determine_exit_code(run_result, findings)


if __name__ == "__main__":
    raise SystemExit(main())

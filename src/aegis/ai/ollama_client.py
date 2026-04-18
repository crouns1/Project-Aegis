"""Minimal local Ollama client for root-cause analysis suggestions."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib import error, request

from ..models import OllamaAnalysisResult, ValgrindFindings


def build_strict_analysis_prompt(
    findings: ValgrindFindings,
    source_snippet: str,
    trace_snippet: str,
) -> str:
    """
    Build a constrained prompt that asks for machine-readable remediation output.

    The model is instructed to emit only JSON with a fixed schema so this output
    can be consumed by downstream CI parsers without additional NLP logic.
    """
    findings_json = json.dumps(findings.to_dict(), indent=2, sort_keys=True)

    return f"""You are a senior C/C++ memory safety and Linux systems debugging assistant.
Analyze the findings and produce root-cause and fix guidance.

RULES:
1) Return ONLY valid JSON.
2) Do not include markdown, backticks, or prose outside JSON.
3) Keep recommendations specific to C/C++ and the provided trace/source.
4) If evidence is weak, state uncertainty explicitly.

REQUIRED JSON SCHEMA:
{{
  "summary": "short one-line diagnosis",
  "root_causes": [
    {{
      "title": "root cause title",
      "confidence": 0.0,
      "evidence": ["fact from trace/source"],
      "fix_strategy": ["step-by-step fix"],
      "safety_checks": ["tests or assertions to add"]
    }}
  ],
  "priority": "low|medium|high|critical"
}}

PARSED_FINDINGS:
{findings_json}

VALGRIND_TRACE_SNIPPET:
{trace_snippet}

SOURCE_SNIPPET:
{source_snippet}
"""


def query_ollama_root_cause(
    findings: ValgrindFindings,
    source_snippet: str,
    trace_snippet: str,
    *,
    model: str = "llama3.1:8b",
    endpoint: str = "http://localhost:11434",
    timeout_seconds: int = 45,
) -> OllamaAnalysisResult:
    """
    Query a local Ollama server using `/api/generate`.

    No third-party dependency is used; request/response handling is done with
    Python's standard urllib stack.
    """
    prompt = build_strict_analysis_prompt(
        findings=findings,
        source_snippet=source_snippet,
        trace_snippet=trace_snippet,
    )

    url = endpoint.rstrip("/") + "/api/generate"
    payload: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            # Low temperature is used to improve determinism for CI logs.
            "temperature": 0.1
        },
    }

    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url=url,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )

    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except error.URLError as exc:
        return OllamaAnalysisResult(
            model=model,
            endpoint=endpoint,
            prompt=prompt,
            raw_response_text="",
            structured_response=None,
            error=f"Ollama connection failed: {exc}",
        )
    except TimeoutError:
        return OllamaAnalysisResult(
            model=model,
            endpoint=endpoint,
            prompt=prompt,
            raw_response_text="",
            structured_response=None,
            error="Ollama request timed out.",
        )

    # Payload from Ollama `/api/generate` typically includes `response`.
    try:
        body_json = json.loads(body)
        raw_response_text = str(body_json.get("response", ""))
    except json.JSONDecodeError:
        return OllamaAnalysisResult(
            model=model,
            endpoint=endpoint,
            prompt=prompt,
            raw_response_text=body,
            structured_response=None,
            error="Ollama returned non-JSON payload.",
        )

    # Try to decode the model's strict JSON response.
    structured: Optional[Dict[str, Any]] = None
    parse_error: Optional[str] = None
    if raw_response_text.strip():
        try:
            parsed = json.loads(raw_response_text)
            if isinstance(parsed, dict):
                structured = parsed
            else:
                parse_error = "Model output was JSON but not an object."
        except json.JSONDecodeError:
            parse_error = "Model response was not valid JSON."

    return OllamaAnalysisResult(
        model=model,
        endpoint=endpoint,
        prompt=prompt,
        raw_response_text=raw_response_text,
        structured_response=structured,
        error=parse_error,
    )

"""Local AI client package."""

from .ollama_client import build_strict_analysis_prompt, query_ollama_root_cause

__all__ = ["build_strict_analysis_prompt", "query_ollama_root_cause"]

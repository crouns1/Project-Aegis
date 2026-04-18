"""Parser package for tracer outputs."""

from .valgrind_parser import parse_valgrind_trace, parse_valgrind_trace_file

__all__ = ["parse_valgrind_trace", "parse_valgrind_trace_file"]

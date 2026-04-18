# Project Aegis (Phase 1 MVP)

Project Aegis is a CI/CD-friendly command-line analyzer for C/C++ executables.
It runs binaries under strict process control, parses Valgrind traces for memory
and file descriptor leaks, and can request local root-cause guidance from Ollama.

This Phase 1 MVP is implemented in Python using only the standard library.

## Directory Layout

```text
project-aegis/
  pyproject.toml
  README.md
  src/
    aegis/
      __init__.py
      cli.py
      models.py
      runner.py
      parsers/
        __init__.py
        valgrind_parser.py
      ai/
        __init__.py
        ollama_client.py
  tests/
    test_valgrind_parser.py
```

## Quick Start

1. Ensure Linux has `valgrind` installed.
2. Build your C/C++ target binary.
3. Run Aegis from this directory:

```bash
PYTHONPATH=src python3 -m aegis.cli \
  --binary ./build/my_binary \
  --valgrind \
  --timeout 30 \
  --output json
```

To include AI analysis with local Ollama:

```bash
PYTHONPATH=src python3 -m aegis.cli \
  --binary ./build/my_binary \
  --valgrind \
  --source ./src/my_file.c \
  --line-start 20 \
  --line-end 80 \
  --ollama-model llama3.1:8b
```

## Notes

- Subprocess calls never use `shell=True`.
- The runner launches processes in a new process group so timeout cleanup can
  terminate child processes, not only the parent process.
- Valgrind parser extracts:
  - `definitely lost` bytes/blocks
  - `indirectly lost` bytes/blocks
  - invalid read/write event counts
  - unclosed file descriptor count

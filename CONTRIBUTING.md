# Contributing

THEncrypterX is a personal project, but issues, bug reports, and small pull
requests are welcome. This document covers the local development workflow.

## Development setup

Requires Python 3.12 or 3.13.

```bash
git clone https://github.com/Emonemon74/THEncrypterX.git
cd THEncrypterX
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

`requirements.txt` installs only what the CLI/library need at runtime
(`cryptography`, `pynacl`, `argon2-cffi`, `typer`, `rich`).
`requirements-dev.txt` adds everything for development: the GUI (PySide6),
the test suite (`pytest`, `pytest-qt`, `pytest-timeout`, `hypothesis`,
`psutil` for benchmarks), and the linters (`ruff`, `mypy`).

Install the package itself in editable mode if you want `thencrypterx` on
your `PATH` while developing:

```bash
pip install -e .
```

## Running the tests

```bash
pytest                              # full suite
pytest tests/test_security.py -v    # the 22-case tamper matrix
pytest -k kdf                       # a subset by name
```

The suite has a 60-second per-test timeout (`pytest-timeout`, configured in
`pyproject.toml`) as a safety net against an accidental hang - a legitimate
test should never come close to it.

GUI tests (`tests/test_gui_main_window.py`) use `pytest-qt` and run
headless; they do not require a visible display.

## Linting and type checking

```bash
ruff check .
ruff format .          # if you want ruff to also reformat
mypy app
```

`mypy` is configured `disallow_untyped_defs = true` for `app/`, with an
exception for `app/gui/*` (PySide6's own stubs make full strictness there
more friction than it's worth). New code outside `app/gui/` should be fully
typed.

## Running benchmarks

```bash
python benchmarks/benchmark_files.py
```

This measures real throughput and memory on your machine - do not copy
numbers from `README.md` (measured on a specific Apple Silicon machine) and
present them as your own environment's results. If you change anything in
the crypto or file-processing path, re-run the benchmark and update the
numbers with what you actually measured.

## Building a standalone executable

```bash
pip install -e ".[gui,build]"
pyinstaller packaging/THEncrypterX.spec
```

Produces `dist/THEncrypterX.app` (macOS) or `dist/THEncrypterX/` (Linux/
Windows) - a onedir bundle, not `--onefile`: faster startup, at the cost of
being a folder instead of a single file (see `packaging/THEncrypterX.spec`
for why, and why UPX compression is off). This packages the desktop GUI
(`main.py`) only; the CLI is distributed through `pip install`, not as a
standalone binary, since anyone running it from a terminal already has
Python.

`.github/workflows/release.yml` builds this on Linux/macOS/Windows and
attaches zipped artifacts to a draft GitHub Release whenever a `v*` tag is
pushed:

```bash
git tag v1.1.0
git push origin v1.1.0
```

The `test` job in that workflow re-runs the full suite on all three
platforms first and gates the build on it - a release is never built from a
commit that hasn't just been proven green everywhere. The release itself is
created as a **draft**, not auto-published; someone reviews the generated
notes and attached binaries before clicking Publish. You can also trigger
the workflow by hand (Actions tab -> Release -> Run workflow) to test the
build/upload steps without cutting a real tag - manual runs still build and
upload artifacts, they just don't create a release.

## Regenerating the known-answer test vector

`tests/test_kat.py` checks a frozen `.thex` file
(`tests/vectors/`) always decodes identically - a compatibility guardrail
against accidental format drift. If you deliberately change the wire format
(and bump the format version), regenerate it:

```bash
python scripts/generate_kat.py
```

Do **not** regenerate the vector to make a failing test pass without
understanding why the format changed - that defeats the point of the
guardrail.

## Pull request expectations

- Add or update tests for any behavior change - this project treats
  `tests/test_security.py` and `tests/test_properties.py` as living
  documentation of what is guaranteed, not just a pass/fail gate
- Run `pytest`, `ruff check .`, and `mypy app` locally before opening a PR;
  CI runs the same checks on Linux/macOS/Windows x Python 3.12/3.13
- If a change affects what is or isn't protected, update
  `docs/threat-model.md` in the same PR
- If a change affects the wire format, update `docs/file-format.md` and the
  format version, and regenerate the KAT vector deliberately
- Keep unrelated changes out of security-sensitive PRs to make them easier
  to review

## Reporting a vulnerability

Do not open a public issue for a security vulnerability - see
[`SECURITY.md`](SECURITY.md) for how to report one privately.

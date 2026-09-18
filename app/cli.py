"""THEncrypterX command-line interface.

A thin wrapper: every command here calls straight into app.files/app.crypto
and only handles argument parsing, password input, progress display, and
mapping exceptions to exit codes. No cryptographic or format logic lives in
this file.

Exit codes:
    0  success
    1  unexpected error
    2  wrong password
    3  corrupt / malformed / unsupported container
    4  cancelled by the user
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn

from app.benchmark import MiB, machine_info_lines, run_benchmark
from app.core.errors import (
    CancelledError,
    FormatError,
    ThexError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
    WrongPasswordError,
)
from app.crypto.cipher import ALGO_AES_256_GCM, ALGO_XCHACHA20_POLY1305
from app.files.decrypt import decrypt_file
from app.files.encrypt import DEFAULT_AEAD_ID, DEFAULT_CHUNK_SIZE, encrypt_file
from app.files.shred import shred_file
from app.files.verify import verify_file
from app.format.container import read_footer_at_end
from app.format.header import Header

app = typer.Typer(add_completion=False, help="THEncrypterX: secure file encryption.")
console = Console()
err_console = Console(stderr=True)

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_WRONG_PASSWORD = 2
EXIT_FORMAT_ERROR = 3
EXIT_CANCELLED = 4

_AEAD_NAMES = {"xchacha20": ALGO_XCHACHA20_POLY1305, "aes256gcm": ALGO_AES_256_GCM}
# The CLI (unlike the encrypt_file/decrypt_file default of 1) parallelizes by
# default, since a real user running this from a terminal on a real file is
# exactly who benefits from it - override with --workers 1 for the original
# single-threaded behaviour.
_DEFAULT_CLI_WORKERS = os.cpu_count() or 1
_AEAD_LABELS = {v: k for k, v in _AEAD_NAMES.items()}


def _exit_code_for(exc: BaseException) -> int:
    if isinstance(exc, WrongPasswordError):
        return EXIT_WRONG_PASSWORD
    if isinstance(exc, (FormatError, UnsupportedVersionError, UnsupportedAlgorithmError)):
        return EXIT_FORMAT_ERROR
    if isinstance(exc, CancelledError):
        return EXIT_CANCELLED
    if isinstance(exc, ThexError):
        return EXIT_FORMAT_ERROR
    return EXIT_UNEXPECTED


def _resolve_password(password_file: Path | None, prompt_text: str, *, confirm: bool) -> str:
    """Never accept a password as a plain CLI flag (shell history would leak it).

    Precedence: THEX_PASSWORD env var (for scripting) -> --password-file
    (for scripting) -> interactive no-echo prompt.
    """
    env_password = os.environ.get("THEX_PASSWORD")
    if env_password:
        return env_password
    if password_file is not None:
        text = password_file.read_text(encoding="utf-8")
        first_line = text.splitlines()[0] if text.splitlines() else ""
        if not first_line:
            err_console.print("[red]--password-file is empty.[/red]")
            raise typer.Exit(code=EXIT_UNEXPECTED)
        return first_line
    return str(typer.prompt(prompt_text, hide_input=True, confirmation_prompt=confirm))


def _make_progress() -> Progress:
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )


@app.command()
def encrypt(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="File to encrypt."),
    output: Path | None = typer.Option(
        None, "-o", "--output", help="Output .thex path (default: <input>.thex)."
    ),
    aead: str = typer.Option(
        _AEAD_LABELS[DEFAULT_AEAD_ID], "--aead", help="xchacha20 or aes256gcm."
    ),
    chunk_size: int = typer.Option(
        DEFAULT_CHUNK_SIZE, "--chunk-size", help="Plaintext bytes per chunk."
    ),
    workers: int = typer.Option(
        _DEFAULT_CLI_WORKERS,
        "--workers",
        min=1,
        help="Chunks to encrypt concurrently (default: CPU count). Both AEAD "
        "backends release the GIL during the actual crypto, so this genuinely "
        "parallelizes - most useful for XChaCha20-Poly1305, which runs in "
        "software. Pass 1 for the original single-threaded behaviour.",
    ),
    password_file: Path | None = typer.Option(
        None, "--password-file", help="Read the password from this file's first line."
    ),
) -> None:
    """Encrypt a file into a .thex container."""
    if aead not in _AEAD_NAMES:
        err_console.print(
            f"[red]Unknown --aead value {aead!r}. Use 'xchacha20' or 'aes256gcm'.[/red]"
        )
        raise typer.Exit(code=EXIT_UNEXPECTED)

    output_path = output if output is not None else input_file.with_name(input_file.name + ".thex")
    password = _resolve_password(password_file, "Password", confirm=True)
    total_size = input_file.stat().st_size or 1

    try:
        with _make_progress() as progress:
            task = progress.add_task("Encrypting", total=total_size)

            def on_progress(done: int, total: int) -> None:
                progress.update(task, completed=done, total=total or 1)

            encrypt_file(
                input_file,
                output_path,
                password,
                aead_id=_AEAD_NAMES[aead],
                chunk_size=chunk_size,
                progress_cb=on_progress,
                workers=workers,
            )
    except KeyboardInterrupt:
        err_console.print("[yellow]Cancelled.[/yellow]")
        raise typer.Exit(code=EXIT_CANCELLED) from None
    except ThexError as exc:
        err_console.print(f"[red]Encryption failed:[/red] {exc}")
        raise typer.Exit(code=_exit_code_for(exc)) from None

    console.print(f"[green]Encrypted[/green] -> {output_path}")


@app.command()
def decrypt(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="A .thex file."),
    output: Path | None = typer.Option(
        None, "-o", "--output", help="Output path (default: original filename, next to input)."
    ),
    workers: int = typer.Option(
        _DEFAULT_CLI_WORKERS,
        "--workers",
        min=1,
        help="Chunks to decrypt concurrently (default: CPU count). Works "
        "regardless of how many workers the file was encrypted with.",
    ),
    password_file: Path | None = typer.Option(
        None, "--password-file", help="Read the password from this file's first line."
    ),
) -> None:
    """Decrypt a .thex container back to its original file."""
    password = _resolve_password(password_file, "Password", confirm=False)

    try:
        with _make_progress() as progress:
            task = progress.add_task("Decrypting", total=1)
            started = {"value": False}

            def on_progress(done: int, total: int) -> None:
                if not started["value"]:
                    progress.update(task, total=total or 1)
                    started["value"] = True
                progress.update(task, completed=done)

            metadata = decrypt_file(
                input_file, output, password, progress_cb=on_progress, workers=workers
            )
    except KeyboardInterrupt:
        err_console.print("[yellow]Cancelled.[/yellow]")
        raise typer.Exit(code=EXIT_CANCELLED) from None
    except FileExistsError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_UNEXPECTED) from None
    except WrongPasswordError:
        err_console.print("[red]Wrong password or corrupted file.[/red]")
        raise typer.Exit(code=EXIT_WRONG_PASSWORD) from None
    except ThexError as exc:
        err_console.print(f"[red]Decryption failed:[/red] {exc}")
        raise typer.Exit(code=_exit_code_for(exc)) from None

    shown_output = output if output is not None else input_file.parent / metadata.original_name
    console.print(f"[green]Decrypted[/green] -> {shown_output}")


@app.command()
def verify(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="A .thex file."),
    workers: int = typer.Option(
        _DEFAULT_CLI_WORKERS,
        "--workers",
        min=1,
        help="Chunks to authenticate concurrently (default: CPU count).",
    ),
    password_file: Path | None = typer.Option(
        None, "--password-file", help="Read the password from this file's first line."
    ),
) -> None:
    """Authenticate a .thex container's header, metadata, and every chunk -
    without writing any plaintext anywhere. Needs the password: confirming a
    container is genuinely intact requires the key that proves it."""
    password = _resolve_password(password_file, "Password", confirm=False)

    try:
        with _make_progress() as progress:
            task = progress.add_task("Verifying", total=1)
            started = {"value": False}

            def on_progress(done: int, total: int) -> None:
                if not started["value"]:
                    progress.update(task, total=total or 1)
                    started["value"] = True
                progress.update(task, completed=done)

            result = verify_file(input_file, password, progress_cb=on_progress, workers=workers)
    except KeyboardInterrupt:
        err_console.print("[yellow]Cancelled.[/yellow]")
        raise typer.Exit(code=EXIT_CANCELLED) from None
    except WrongPasswordError:
        console.print("Container:        [red]INVALID[/red]")
        console.print("Metadata:         [red]FAILED[/red] (wrong password, or tampered)")
        err_console.print("[red]Wrong password or corrupted file.[/red]")
        raise typer.Exit(code=EXIT_WRONG_PASSWORD) from None
    except ThexError as exc:
        console.print("Container:        [red]INVALID[/red]")
        console.print(f"Integrity:        [red]FAILED[/red] ({exc})")
        raise typer.Exit(code=_exit_code_for(exc)) from None

    aead_label = _AEAD_LABELS.get(result.aead_id, f"unknown({result.aead_id})")
    console.print("Container:        [green]VALID[/green]")
    console.print(f"Format version:   {result.format_version}")
    console.print(f"Algorithm:        {aead_label}")
    console.print(f"Chunks:           {result.total_chunks}")
    console.print(f"Original size:    {result.original_size} bytes")
    console.print("Metadata:         [green]VALID[/green]")
    console.print("Authentication:   [green]VALID[/green]")
    console.print("Integrity:        [green]PASS[/green]")


@app.command()
def inspect(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="A .thex file."),
) -> None:
    """Print .thex container header fields. Needs no password - the header
    is not encrypted (only its contents are)."""
    try:
        with input_file.open("rb") as f:
            header = Header.read_from(f)
            total_chunks, _ = read_footer_at_end(f)
    except ThexError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=_exit_code_for(exc)) from None

    aead_label = _AEAD_LABELS.get(header.aead_id, f"unknown({header.aead_id})")
    p = header.argon2_params
    console.print(f"format_version: {header.format_version}")
    console.print(f"aead: {aead_label}")
    console.print(f"chunk_size: {header.chunk_size}")
    console.print(
        "argon2: "
        f"memory_cost_kib={p.memory_cost_kib} time_cost={p.time_cost} parallelism={p.parallelism}"
    )
    console.print(f"salt: {header.salt.hex()}")
    console.print(f"total_chunks: {total_chunks}")


@app.command()
def benchmark(
    size_mb: int = typer.Option(100, "--size-mb", min=1, help="File size to benchmark, in MB."),
    workers: list[int] = typer.Option(
        [1, _DEFAULT_CLI_WORKERS],
        "--workers",
        help="Worker counts to compare (repeat the flag for several, e.g. "
        "--workers 1 --workers 4 --workers 8). Default: 1 and the CPU count.",
    ),
    aead: str = typer.Option(
        "both", "--aead", help="xchacha20, aes256gcm, or both (default)."
    ),
    runs: int = typer.Option(
        3, "--runs", min=1, help="Runs per configuration (median reported)."
    ),
) -> None:
    """Measure real encrypt/decrypt throughput on this machine.

    Generates a temporary random file, encrypts and decrypts it with each
    algorithm/worker combination, and reports median throughput. Real
    measurements only - see docs/performance.md for methodology notes and
    benchmarks/benchmark_files.py for the full Markdown-table sweep used to
    update that document.
    """
    if aead == "both":
        algo_ids = [ALGO_XCHACHA20_POLY1305, ALGO_AES_256_GCM]
    elif aead in _AEAD_NAMES:
        algo_ids = [_AEAD_NAMES[aead]]
    else:
        err_console.print(
            f"[red]Unknown --aead value {aead!r}. Use 'xchacha20', 'aes256gcm', or 'both'.[/red]"
        )
        raise typer.Exit(code=EXIT_UNEXPECTED)

    for line in machine_info_lines(runs):
        console.print(line)

    console.print(f"File size:        {size_mb} MB\n")

    for algo_id in algo_ids:
        console.print(f"[bold]{_AEAD_LABELS[algo_id]}[/bold]")
        for worker_count in workers:
            result = run_benchmark(
                size_bytes=size_mb * MiB,
                aead_id=algo_id,
                chunk_size=DEFAULT_CHUNK_SIZE,
                runs=runs,
                workers=worker_count,
            )
            console.print(
                f"  Workers: {worker_count:<4} "
                f"encrypt {result['encrypt_mb_s']:.1f} MB/s   "
                f"decrypt {result['decrypt_mb_s']:.1f} MB/s"
            )
        console.print("")


@app.command()
def shred(
    target: Path = typer.Argument(..., exists=True, help="File to overwrite and delete."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Best-effort overwrite-then-delete.

    Does NOT guarantee unrecoverable erasure on SSDs, copy-on-write
    filesystems, or where backups/snapshots exist. See docs/threat-model.md.
    """
    if not yes:
        confirmed = typer.confirm(
            f"Overwrite and delete {target}? This does not guarantee unrecoverable "
            "erasure on SSDs or modern filesystems.",
            default=False,
        )
        if not confirmed:
            console.print("Aborted.")
            raise typer.Exit(code=EXIT_CANCELLED)

    try:
        shred_file(target)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_UNEXPECTED) from None

    console.print(f"[green]Shredded[/green] {target}")


if __name__ == "__main__":
    app()

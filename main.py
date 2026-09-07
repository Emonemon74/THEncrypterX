"""Launch the THEncrypterX desktop GUI.

The CLI entry point is ``app.cli:app`` (installed as the ``thencrypterx``
command). This file only exists to start the graphical application.
"""

from __future__ import annotations


def main() -> None:
    try:
        from app.gui.main_window import run
    except ImportError:
        raise SystemExit(
            "The GUI needs PySide6. Install it with:  pip install -r requirements-dev.txt"
        ) from None
    run()


if __name__ == "__main__":
    main()

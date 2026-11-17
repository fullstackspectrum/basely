"""Basely: compare container base images on vulnerabilities, size and fit, and pick a better one."""

__version__ = "1.0.0"


def main() -> None:
    from .cli import main as _main

    _main()

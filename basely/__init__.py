"""Basely: compare container base images on vulnerabilities, size and fit, and pick a better one."""

__version__ = "0.1.0"


def main() -> None:
    from .cli import main as _main

    _main()

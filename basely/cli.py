"""Command-line interface."""

from __future__ import annotations

import argparse
import inspect
import re
import shutil
import sys
from pathlib import Path

from . import __version__, dockerfile
from .advise import FAIL_ON_CHOICES, Advice, Advisor
from .cache import Cache
from .dockerfile import Stage
from .errors import BaselyError
from .osv import Client
from .refs import parse
from .registry import Registry
from .render import to_json, to_markdown, to_text, use_colour

# Exit codes: 0 clean (or nothing gated), 1 a --fail-on category was hit,
# 2 bad usage, an unreadable Dockerfile or an image that can't be read.
EXIT_OK, EXIT_GATED, EXIT_ERROR = 0, 1, 2

SOURCES = ("official", "hardened", "chainguard", "upgrade")


def _fail_on(value: str) -> set[str]:
    kinds = {v.strip().lower() for v in value.split(",") if v.strip()}
    unknown = kinds - set(FAIL_ON_CHOICES)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown category {', '.join(sorted(unknown))} (choose from {', '.join(FAIL_ON_CHOICES)})"
        )
    return kinds


def _sources(value: str) -> tuple[str, ...]:
    picked = tuple(v.strip().lower() for v in value.split(",") if v.strip())
    unknown = set(picked) - set(SOURCES)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown source {', '.join(sorted(unknown))} (choose from {', '.join(SOURCES)})"
        )
    return picked


def _platform(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?", value):
        raise argparse.ArgumentTypeError(f"{value!r} should look like linux/amd64")
    return value


# ── Help ──────────────────────────────────────────────────────────────

REPO = "https://github.com/fullstackspectrum/basely"

ADVISE_EPILOG = """\
sources:
  official              Docker Official Images: -slim, -alpine and the full image
  hardened              Docker Hardened Images on dhi.io (needs docker login dhi.io)
  chainguard            Chainguard's free images on cgr.dev (latest only)
  upgrade               the newest release of the same runtime (Python 3.12 → 3.14)

fail-on categories:
  fixable               the current image has advisories a rebuild or pull would fix
  critical              the current image has a critical advisory
  better                Basely recommends a different image
  root                  the final image runs as root

exit codes:
  0                     passed, or nothing in --fail-on occurred
  1                     a --fail-on category occurred
  2                     bad usage, or a Dockerfile or image that can't be read

examples:
  $ basely advise                                       # ./Dockerfile
  $ basely advise services/api/Dockerfile --html advice.html
  $ basely advise --image python:3.12                   # no Dockerfile needed
  $ basely advise --only official,hardened --fail-on better
  $ basely advise --with registry.example.com/base/python:3.12
"""

COMPARE_EPILOG = """\
examples:
  $ basely compare python:3.12 python:3.12-slim dhi.io/python:3.12
  $ basely compare node:22 node:22-alpine --platform linux/arm64
"""

ROOT_EPILOG = f"""\
examples:
  $ basely advise                                       # ./Dockerfile
  $ basely compare python:3.12 python:3.12-slim
  $ basely advise --help                                # every option for advise

docs:
  {REPO}
"""

# Brand colours as terminal codes: flags take blue-soft (keys in code),
# placeholders yellow (strings), headings the // eyebrow.
_HELP_STYLES = {"flag": "94", "meta": "33", "dim": "2", "bold": "1", "red": "31"}


def _style(code: str, text: str) -> str:
    return f"\033[{_HELP_STYLES[code]}m{text}\033[0m"


def _colourise_help(text: str) -> str:
    out = []
    section = ""
    for line in text.splitlines():
        heading = re.fullmatch(r"([a-z][a-z -]*):", line)
        if heading:
            section = heading.group(1)
            out.append(f"{_style('dim', '//')} {_style('bold', section)}")
            continue
        if line.startswith("usage:"):
            out.append(f"{_style('dim', '//')} {_style('bold', 'usage')}")
            out.append("  " + re.sub(r"\b(basely(?: advise| compare)?)\b", lambda m: _style("red", m.group(1)),
                                     line[7:], count=1))
            continue
        if section == "examples" and line.lstrip().startswith("$"):
            cmd, _, comment = line.partition("#")
            cmd = cmd.replace("$", _style("dim", "$"), 1)
            out.append(cmd + (_style("dim", "#" + comment) if comment else ""))
            continue
        if section == "docs":
            out.append(_style("flag", line))
            continue
        m = re.match(r"^(  )(\S.*?)(\s{2,}\S.*)?$", line)
        if m and section not in ("", "usage"):
            term = re.sub(r"(?<![\w-])(--?[\w-]+)", lambda x: _style("flag", x.group(1)), m.group(2))
            term = re.sub(r"(?<![\w-])([A-Z]+)\b", lambda x: _style("meta", x.group(1)), term)
            if section in ("fail-on categories", "commands", "exit codes", "sources"):
                term = _style("flag", m.group(2))
            out.append(m.group(1) + term + (m.group(3) or ""))
            continue
        out.append(line)
    return "\n".join(out) + "\n"


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str) -> None:
        width = min(shutil.get_terminal_size((100, 24)).columns, 100)
        super().__init__(prog, max_help_position=24, width=width)
        # Pin the help column at 24 in every section, so options and the
        # hand-written reference sections in the epilog line up.
        self._action_max_length = 22

    def _format_action(self, action: argparse.Action) -> str:
        # List subcommands directly under "commands:", without argparse's
        # extra "COMMAND" line above them.
        if isinstance(action, argparse._SubParsersAction):
            return "".join(self._format_action(a) for a in action._get_subactions())
        return super()._format_action(action)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        # "-p, --platform P" rather than argparse's "-p P, --platform P".
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        metavar = self._format_args(action, self._get_default_metavar_for_optional(action))
        return f"{', '.join(action.option_strings)} {metavar}"


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose help is grouped, wrapped to the terminal and, on a
    colour terminal, styled in the Full-Stack-Spectrum palette."""

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("formatter_class", _HelpFormatter)
        kwargs.setdefault("add_help", False)
        # Python 3.14 colours help itself; this parser does its own.
        if "color" in inspect.signature(argparse.ArgumentParser.__init__).parameters:
            kwargs.setdefault("color", False)
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        text = super().format_help()
        return _colourise_help(text) if use_colour() else text


def _help_flag(group) -> None:
    group.add_argument("-h", "--help", action="help", help="show this help and exit")


def _common(p: argparse.ArgumentParser, gate: bool) -> None:
    scan = p.add_argument_group("scanning")
    scan.add_argument("-p", "--platform", type=_platform, default="linux/amd64", metavar="P",
                      help="platform to compare (default: linux/amd64)")
    scan.add_argument("--no-cache", action="store_true",
                      help="don't read or write the cache in ~/.cache/basely")

    output = p.add_argument_group("output")
    output.add_argument("-f", "--format", choices=("text", "markdown", "json"), default="text",
                        metavar="FORMAT", help="what to print: text (default), markdown or json")
    output.add_argument("--html", metavar="FILE", type=Path,
                        help="write a self-contained HTML report that works offline")
    output.add_argument("--markdown", metavar="FILE", type=Path, help="write a Markdown summary for a PR comment")
    output.add_argument("--json", metavar="FILE", type=Path, help="write everything, every advisory included, as JSON")
    output.add_argument("-v", "--verbose", action="store_true", help="list every candidate's fit notes in the terminal")
    output.add_argument("-q", "--quiet", action="store_true", help="print nothing to stdout")

    if gate:
        g = p.add_argument_group("ci gating")
        g.add_argument("--fail-on", metavar="LIST", type=_fail_on, default=set(),
                       help="exit 1 if any of these comma-separated categories occur (see below)")

    display = p.add_argument_group("display")
    display.add_argument("--title", default="", metavar="TEXT", help="title for the HTML and Markdown reports")
    display.add_argument("--theme", choices=("dark", "light"), default="dark", metavar="THEME",
                         help="HTML report theme: dark (default) or light")
    display.add_argument("--no-color", action="store_true",
                         help="plain terminal output; NO_COLOR and FORCE_COLOR are respected too")
    _help_flag(display)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="basely",
        usage="basely COMMAND [options]",
        description=f"basely {__version__}: compare container base images on vulnerabilities, "
                    "size and fit, and pick a better one.",
        epilog=ROOT_EPILOG,
    )
    sub = parser.add_subparsers(dest="command", title="commands", metavar="COMMAND", parser_class=_Parser)
    general = parser.add_argument_group("options")
    _help_flag(general)
    general.add_argument("--version", action="version", version=f"basely {__version__}",
                         help="print the version and exit")

    a = sub.add_parser(
        "advise",
        help="suggest better base images for each stage of a Dockerfile",
        usage="basely advise [DOCKERFILE] [options]",
        description=(
            "Compare each FROM in a Dockerfile with official slim and Alpine variants, Docker\n"
            "Hardened Images, Chainguard images and newer runtimes. Every candidate is checked\n"
            "against OSV for vulnerabilities and against the stage for fit: a stage with RUN\n"
            "steps needs a shell, and apt-get needs a Debian or Ubuntu base."
        ),
        epilog=ADVISE_EPILOG,
    )
    inputs = a.add_argument_group("arguments")
    inputs.add_argument("dockerfile", metavar="DOCKERFILE", nargs="?", type=Path, default=Path("Dockerfile"),
                        help="the Dockerfile to read (default: ./Dockerfile)")
    inputs.add_argument("-i", "--image", metavar="REF",
                        help="advise on an image instead of a Dockerfile")
    inputs.add_argument("--role", choices=("runtime", "build"), default="runtime", metavar="ROLE",
                        help="with --image: runtime (default) for a shipped image, build if you RUN on it")
    cands = a.add_argument_group("candidates")
    cands.add_argument("--only", type=_sources, default=SOURCES, metavar="LIST",
                       help="comma-separated sources to suggest from (default: all, see below)")
    cands.add_argument("-w", "--with", dest="extra", action="append", default=[], metavar="REF",
                       help="also compare this image, e.g. your own golden base (repeatable)")
    _common(a, gate=True)

    c = sub.add_parser(
        "compare",
        help="compare images you name, side by side",
        usage="basely compare IMAGE IMAGE... [options]",
        description="Compare images side by side. The first is the baseline the others are judged against.",
        epilog=COMPARE_EPILOG,
    )
    cinputs = c.add_argument_group("arguments")
    cinputs.add_argument("images", metavar="IMAGE", nargs="+", help="image references; the first is the baseline")
    _common(c, gate=False)
    return parser


def _write(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise BaselyError(f"{path}: can't write ({exc.strerror})") from None


def _stages(args: argparse.Namespace) -> tuple[list[Stage], str]:
    if args.command == "compare":
        if len(args.images) < 2:
            raise BaselyError("compare needs at least two images")
        first = str(parse(args.images[0]))
        return [Stage(0, 0, first, first, final=True, assumed_role="runtime")], "compare"
    if args.image:
        ref = str(parse(args.image))
        return [Stage(0, 0, ref, ref, final=True, assumed_role=args.role)], ref
    path: Path = args.dockerfile
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        hint = " (or use --image to advise on an image)" if str(path) == "Dockerfile" else ""
        raise BaselyError(f"{path}: no such file{hint}") from None
    except OSError as exc:
        raise BaselyError(f"{path}: can't read ({exc.strerror})") from None
    try:
        return dockerfile.parse(text), str(path)
    except BaselyError as exc:
        raise BaselyError(f"{path}: {exc}") from None


def run(args: argparse.Namespace) -> int:
    stages, source = _stages(args)
    cache = Cache(enabled=not args.no_cache)
    show_progress = not args.quiet and sys.stderr.isatty()

    def progress(msg: str) -> None:
        if show_progress:
            print(f"\033[2m  {msg}…\033[0m" if use_colour(sys.stderr) else f"  {msg}…", file=sys.stderr)

    if args.command == "compare":
        include: tuple[str, ...] = ()
        extra = [str(parse(r)) for r in args.images[1:]]
    else:
        include = args.only
        extra = [str(parse(r)) for r in args.extra]

    advisor = Advisor(Registry(cache), Client(cache), platform=args.platform, include=include, progress=progress)
    advice: Advice = advisor.advise(stages, extra)
    advice.source = source
    if args.title == "" and args.command == "compare":
        args.title = "Image comparison"

    fail_on: set[str] = getattr(args, "fail_on", set())
    colour = use_colour() and not args.no_color

    if args.html:
        from .html import to_html  # Only pay for loading the fonts when asked.

        _write(args.html, to_html(advice, theme=args.theme, title=args.title))
    if args.markdown:
        _write(args.markdown, to_markdown(advice, title=args.title))
    if args.json:
        _write(args.json, to_json(advice, fail_on))

    if not args.quiet:
        if args.format == "json":
            sys.stdout.write(to_json(advice, fail_on))
        elif args.format == "markdown":
            sys.stdout.write(to_markdown(advice, title=args.title))
        else:
            sys.stdout.write(to_text(advice, colour=colour, verbose=args.verbose))

    unreadable = [sa.current for sa in advice.stages if sa.current.image is None]
    if unreadable:
        sys.stdout.flush()
        for c in unreadable:
            print(f"basely: {c.ref}: {c.error}", file=sys.stderr)
        return EXIT_ERROR

    hits = advice.triggered(fail_on)
    if hits:
        summary = ", ".join(f"{kind} ({n})" for kind, n in hits.items())
        # Keep the report above the verdict when both go to a terminal.
        sys.stdout.flush()
        print(f"basely: failing because of {summary}", file=sys.stderr)
        return EXIT_GATED
    return EXIT_OK


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in ("advise", "compare"):
        parser.print_help()
        sys.exit(EXIT_ERROR)
    try:
        sys.exit(run(args))
    except BaselyError as exc:
        print(f"basely: {exc}", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        sys.exit(130)

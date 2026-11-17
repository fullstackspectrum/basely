"""Read a Dockerfile's stages: each FROM, and what the stage does on top of it.

Only what affects the choice of base image is kept: whether the stage runs
commands (so it needs a shell), which package manager those commands use, and
whether it switches user first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .errors import BaselyError

_PACKAGE_COMMANDS = {
    "apt": re.compile(r"\b(apt-get|apt)\s+(-\S+\s+)*(install|update|upgrade)\b"),
    "apk": re.compile(r"\bapk\s+(-\S+\s+)*(add|update|upgrade)\b"),
    "dnf": re.compile(r"\b(dnf|microdnf|yum)\s+(-\S+\s+)*install\b"),
}


@dataclass
class Stage:
    index: int
    line: int
    image: str          # after ARG substitution
    raw: str            # as written
    name: str = ""
    platform: str = ""
    parent: str = ""    # set when FROM names an earlier stage instead of an image
    runs: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    final: bool = False
    assumed_role: str = ""  # set when advising on a bare image with no Dockerfile

    @property
    def is_image(self) -> bool:
        return not self.parent and self.image.lower() != "scratch"

    @property
    def needs_shell(self) -> bool:
        if self.assumed_role:
            return self.assumed_role == "build"
        # Exec-form RUN ["bin", ...] doesn't go through a shell.
        return any(not r.lstrip().startswith("[") for r in self.runs)

    @property
    def package_manager(self) -> str:
        text = "\n".join(self.runs)
        return next((pm for pm, rx in _PACKAGE_COMMANDS.items() if rx.search(text)), "")

    @property
    def switches_to_root(self) -> bool:
        return any(u.split(":")[0] in ("root", "0") for u in self.users)

    @property
    def role(self) -> str:
        """runtime: the shipped image with nothing run on top; build: everything else."""
        if self.assumed_role:
            return self.assumed_role
        return "runtime" if self.final and not self.runs else "build"

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        return "final stage" if self.final else f"stage {self.index}"


def _logical_lines(text: str) -> list[tuple[int, str]]:
    escape = "\\"
    m = re.match(r"(?:\s*#\s*\w+\s*=.*\n)*?\s*#\s*escape\s*=\s*(\S)", text, re.I)
    if m:
        escape = m.group(1)
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue  # comments inside a continued instruction are dropped
        if not buf:
            start = n
        if line.rstrip().endswith(escape):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        out.append((start, buf.strip()))
        buf = ""
    if buf.strip():
        out.append((start, buf.strip()))
    return out


def _substitute(value: str, args: dict[str, str]) -> str:
    def repl(m: re.Match) -> str:
        name = m.group(1) or m.group(4)
        op, word = m.group(2), m.group(3) or ""
        current = args.get(name, "")
        if op == ":-":
            return current or word
        if op == "-":
            return current if name in args else word
        if op == ":+":
            return word if current else ""
        return current

    return re.sub(r"\$\{(\w+)(?:(:?[-+])([^}]*))?\}|\$(\w+)", repl, value)


def parse(text: str) -> list[Stage]:
    args: dict[str, str] = {}
    stages: list[Stage] = []
    names: set[str] = set()

    for line_no, line in _logical_lines(text):
        keyword, _, rest = line.partition(" ")
        keyword = keyword.upper()
        rest = rest.strip()

        if keyword == "ARG":
            # Only ARGs before the first FROM can be used in FROM lines.
            if not stages:
                for part in re.findall(r"(\w+)(?:=(\"[^\"]*\"|'[^']*'|\S*))?", rest):
                    args[part[0]] = part[1].strip("\"'")
            continue

        if keyword == "FROM":
            platform = ""
            tokens = rest.split()
            while tokens and tokens[0].startswith("--"):
                flag = tokens.pop(0)
                if flag.startswith("--platform="):
                    # Kept as written: $BUILDPLATFORM and friends are set by
                    # the builder, not by ARG, and Basely only reprints it.
                    platform = flag.split("=", 1)[1]
            if not tokens:
                raise BaselyError(f"line {line_no}: FROM without an image")
            raw = tokens[0]
            name = tokens[2] if len(tokens) >= 3 and tokens[1].upper() == "AS" else ""
            image = _substitute(raw, args)
            stage = Stage(index=len(stages), line=line_no, image=image, raw=raw, name=name, platform=platform)
            if image.lower() in names:
                stage.parent = image.lower()
            stages.append(stage)
            if name:
                names.add(name.lower())
            continue

        if not stages:
            continue
        if keyword == "RUN":
            # Drop RUN's own flags (--mount, --network) so they don't look like commands.
            stages[-1].runs.append(re.sub(r"^(--\S+\s+)*", "", rest))
        elif keyword == "USER":
            stages[-1].users.append(rest)

    if not stages:
        raise BaselyError("no FROM instruction found")
    stages[-1].final = True
    return stages

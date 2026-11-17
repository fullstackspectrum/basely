"""Which images to suggest in place of a given base image.

Each family lists its alternatives as tag templates, split by stage role: a
build stage runs commands, so it needs a shell and package manager (Docker
Hardened Images' and Chainguard's -dev variants); a runtime stage doesn't, so
it gets the minimal variants. {v} is the current runtime version, cut to the
family's precision (3.12 for Python, 22 for Node).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Image
from .refs import ImageRef

_TAG = re.compile(r"^(\d+(?:\.\d+){0,2})(?:-(.+))?$")


@dataclass(frozen=True)
class Family:
    key: str
    label: str
    names: tuple[str, ...]       # repository basenames that belong to this family
    precision: int               # version parts kept: 2 → 3.12, 1 → 22
    env: str = ""                # where official images record the runtime version
    package: str = ""            # ...and the package that carries it elsewhere
    official: dict[str, tuple[str, ...]] = field(default_factory=dict)
    hardened: dict[str, tuple[str, ...]] = field(default_factory=dict)
    chainguard: dict[str, tuple[str, ...]] = field(default_factory=dict)
    next_versions: str = "minor"  # minor, even-major, lts:<list> or "" for none
    os: bool = False             # an OS base rather than a language runtime


_DEBIAN_CODENAMES = {"11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}

FAMILIES: tuple[Family, ...] = (
    Family(
        "python", "Python", ("python", "python3"), 2, env="PYTHON_VERSION", package=r"(?:lib)?python-?(3\.\d+)",
        official={"build": ("python:{v}-slim", "python:{v}-alpine", "python:{v}"),
                  "runtime": ("python:{v}-slim", "python:{v}-alpine")},
        hardened={"build": ("dhi.io/python:{v}-dev", "dhi.io/python:{v}-alpine-dev"),
                  "runtime": ("dhi.io/python:{v}", "dhi.io/python:{v}-alpine")},
        chainguard={"build": ("cgr.dev/chainguard/python:latest-dev",),
                    "runtime": ("cgr.dev/chainguard/python:latest",)},
    ),
    Family(
        "node", "Node.js", ("node", "nodejs"), 1, env="NODE_VERSION", package=r"nodejs-?(\d+)",
        official={"build": ("node:{v}-slim", "node:{v}-alpine", "node:{v}"),
                  "runtime": ("node:{v}-slim", "node:{v}-alpine")},
        hardened={"build": ("dhi.io/node:{v}-dev", "dhi.io/node:{v}-alpine-dev"),
                  "runtime": ("dhi.io/node:{v}", "dhi.io/node:{v}-alpine")},
        chainguard={"build": ("cgr.dev/chainguard/node:latest-dev",),
                    "runtime": ("cgr.dev/chainguard/node:latest",)},
        next_versions="even-major",
    ),
    Family(
        "golang", "Go", ("golang", "go"), 2, env="GOLANG_VERSION", package=r"go-?(1\.\d+)",
        official={"build": ("golang:{v}", "golang:{v}-alpine"), "runtime": ("golang:{v}", "golang:{v}-alpine")},
        hardened={"build": ("dhi.io/golang:{v}-dev", "dhi.io/golang:{v}-alpine-dev"),
                  "runtime": ("dhi.io/golang:{v}", "dhi.io/golang:{v}-alpine")},
        chainguard={"build": ("cgr.dev/chainguard/go:latest-dev",), "runtime": ("cgr.dev/chainguard/go:latest",)},
    ),
    Family(
        "java", "Java", ("eclipse-temurin", "temurin", "openjdk", "amazoncorretto", "jre", "jdk"), 1,
        env="JAVA_VERSION", package=r"openjdk-(\d+)",
        official={"build": ("eclipse-temurin:{v}-jdk", "eclipse-temurin:{v}-jdk-alpine"),
                  "runtime": ("eclipse-temurin:{v}-jre", "eclipse-temurin:{v}-jre-alpine")},
        hardened={"build": ("dhi.io/eclipse-temurin:{v}-dev", "dhi.io/eclipse-temurin:{v}-alpine-dev"),
                  "runtime": ("dhi.io/eclipse-temurin:{v}", "dhi.io/eclipse-temurin:{v}-alpine")},
        chainguard={"build": ("cgr.dev/chainguard/jdk:latest-dev",), "runtime": ("cgr.dev/chainguard/jre:latest",)},
        next_versions="lts:8,11,17,21,25,29",
    ),
    Family(
        "debian", "Debian", ("debian", "debian-base"), 1, os=True,
        official={"build": ("debian:{v}-slim", "debian:{v}"), "runtime": ("debian:{v}-slim",)},
        hardened={"build": ("dhi.io/debian-base:{codename}-dev",), "runtime": ("dhi.io/debian-base:{codename}",)},
        chainguard={"build": ("cgr.dev/chainguard/wolfi-base:latest",),
                    "runtime": ("cgr.dev/chainguard/glibc-dynamic:latest",)},
        next_versions="",
    ),
    Family(
        "ubuntu", "Ubuntu", ("ubuntu",), 2, os=True,
        official={"build": ("ubuntu:{v}", "debian:stable-slim"), "runtime": ("ubuntu:{v}", "debian:stable-slim")},
        hardened={"build": ("dhi.io/debian-base:trixie-dev",), "runtime": ("dhi.io/debian-base:trixie",)},
        chainguard={"build": ("cgr.dev/chainguard/wolfi-base:latest",),
                    "runtime": ("cgr.dev/chainguard/glibc-dynamic:latest",)},
        next_versions="ubuntu-lts",
    ),
    Family(
        "alpine", "Alpine", ("alpine", "alpine-base"), 2, os=True,
        official={"build": ("alpine:{v}",), "runtime": ("alpine:{v}",)},
        hardened={"build": ("dhi.io/alpine-base:{v}-dev",), "runtime": ("dhi.io/alpine-base:{v}",)},
        chainguard={"build": ("cgr.dev/chainguard/wolfi-base:latest",), "runtime": ("cgr.dev/chainguard/wolfi-base:latest",)},
    ),
)

_BY_NAME = {name: f for f in FAMILIES for name in f.names}


def family_for(ref: ImageRef) -> Family | None:
    base = ref.basename
    if base in _BY_NAME:
        return _BY_NAME[base]
    # distroless names its images python3-debian12, nodejs22-debian12, java21-debian12.
    m = re.match(r"(python3|nodejs|java)\d*-", base)
    if m:
        return _BY_NAME.get({"java": "jre"}.get(m.group(1), m.group(1)))
    return None


def split_tag(tag: str) -> tuple[str, str]:
    """python:3.12.7-slim-bookworm → ("3.12.7", "slim-bookworm")."""
    m = _TAG.match(tag)
    return (m.group(1), m.group(2) or "") if m else ("", tag)


def runtime_version(family: Family, image: Image) -> str:
    """The full runtime version an image ships, e.g. 3.12.7, or "" if unknown."""
    if family.os:
        return image.distro.version_id
    if family.env and image.env.get(family.env):
        value = image.env[family.env]
        m = re.search(r"\d+(?:\.\d+)*", value)  # JAVA_VERSION is jdk-21.0.5+11
        return m.group(0) if m else ""
    if family.package:
        rx = re.compile(family.package + r"(?:-[a-z]+)*$")
        for p in image.packages:
            m = rx.fullmatch(p.name)
            if m:
                full = re.match(r"\d+(?:\.\d+)*", p.version.split(":")[-1])
                version = full.group(0) if full else ""
                return version if version.startswith(m.group(1)) else m.group(1)
    return ""


def cut(version: str, precision: int) -> str:
    return ".".join(version.split(".")[:precision])


@dataclass(frozen=True)
class Suggestion:
    ref: str
    source: str     # official, hardened, chainguard, upgrade
    note: str = ""


def suggestions(family: Family, version: str, role: str) -> list[Suggestion]:
    v = cut(version, family.precision) if version else ""
    out: list[Suggestion] = []
    for source, table in (("official", family.official), ("hardened", family.hardened),
                          ("chainguard", family.chainguard)):
        for template in table.get(role, ()):
            if "{v}" in template and not v:
                continue
            if "{codename}" in template:
                codename = _DEBIAN_CODENAMES.get(v)
                if not codename:
                    continue
                template = template.replace("{codename}", codename)
            out.append(Suggestion(template.replace("{v}", v), source))
    return out


def next_version_candidates(family: Family, version: str) -> list[str]:
    """Newer runtime versions worth probing for, nearest first."""
    v = cut(version, family.precision) if version else ""
    if not v or not family.next_versions:
        return []
    parts = [int(p) for p in v.split(".") if p.isdigit()]
    if not parts:
        return []
    if family.next_versions == "minor" and len(parts) >= 2:
        return [f"{parts[0]}.{parts[1] + n}" for n in range(1, 5)]
    if family.next_versions == "even-major":
        start = parts[0] + (2 if parts[0] % 2 == 0 else 1)
        return [str(start + 2 * n) for n in range(4)]
    if family.next_versions.startswith("lts:"):
        lts = [int(x) for x in family.next_versions[4:].split(",")]
        return [str(x) for x in lts if x > parts[0]]
    if family.next_versions == "ubuntu-lts" and len(parts) == 2:
        return [f"{parts[0] + 2 * n}.04" for n in range(1, 4)]
    return []

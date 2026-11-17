"""Find language packages in an image: what pip, npm, Go, Maven and RubyGems put
there, as opposed to the distro's own packages.

Each finder looks at a file's path (and, for Go binaries, its mode) to decide
whether the layer scanner should read it, then parses what it read. Files the
distro's package manager owns are dropped later, in packages.read(), so a
Wolfi py3-pip or an Alpine npm isn't counted twice.
"""

from __future__ import annotations

import io
import json
import re
import zipfile

from .model import Package

# Ceilings on what's read into memory. A base image with a bigger file than
# these is unusual, and skipping one file only loses that file's packages.
MAX_METADATA = 1_000_000
MAX_BINARY = 256_000_000
MAX_ARCHIVE = 256_000_000
MAX_NESTED = 64_000_000

_PY_METADATA = re.compile(r"(?:^|/)site-packages/[^/]+\.dist-info/METADATA$")
_PY_EGG = re.compile(r"(?:^|/)site-packages/[^/]+\.egg-info(?:/PKG-INFO)?$")
_NPM = re.compile(r"(?:^|/)node_modules/(?:@[^/]+/)?[^/]+/package\.json$")
_GEMSPEC = re.compile(r"(?:^|/)specifications/(?P<name>[^/]+?)-(?P<version>\d[\w.]*)(?:-[\w-]+)?\.gemspec$")
_ARCHIVE = re.compile(r"\.(?:jar|war|ear)$")
# Places a Go binary in a base image lives; scanning every executable in
# /usr/lib would read a lot of C libraries for nothing.
_BIN_DIRS = re.compile(r"^(?:usr/(?:local/)?)?s?bin/|^usr/local/go/(?:bin|pkg/tool)/|^usr/lib/go[\w.-]*/(?:bin|pkg/tool)/|^(?:opt|app|ko-app)/")

_GO_MAGIC = b"\xff Go buildinf:"
_ELF = b"\x7fELF"


def kind(path: str, size: int, executable: bool) -> str:
    """Which finder wants this file, or "" for none."""
    if _PY_METADATA.search(path) or _PY_EGG.search(path):
        return "python" if size <= MAX_METADATA else ""
    if _NPM.search(path):
        return "npm" if size <= MAX_METADATA else ""
    if _GEMSPEC.search(path):
        return "gem"
    if _ARCHIVE.search(path):
        return "java" if size <= MAX_ARCHIVE else ""
    if executable and 4096 < size <= MAX_BINARY and _BIN_DIRS.search(path):
        return "go"
    return ""


def parse(kind_: str, path: str, data: bytes) -> list[Package]:
    try:
        if kind_ == "python":
            return _python(path, data)
        if kind_ == "npm":
            return _npm(path, data)
        if kind_ == "gem":
            m = _GEMSPEC.search(path)
            return [Package(m.group("name"), m.group("version"), ecosystem="RubyGems", path=path)] if m else []
        if kind_ == "java":
            return _java(path, data)
        if kind_ == "go":
            return go_buildinfo(path, data)
    except (ValueError, KeyError, zipfile.BadZipFile, UnicodeDecodeError, EOFError):
        pass  # A malformed file is someone else's problem; skip it.
    return []


# ── Python ───────────────────────────────────────────────────────────

def _python(path: str, data: bytes) -> list[Package]:
    name = version = ""
    for line in data.decode("utf-8", "replace").splitlines():
        if not line.strip():
            break  # headers end at the first blank line
        key, sep, value = line.partition(":")
        if not sep:
            continue
        if key == "Name":
            name = value.strip()
        elif key == "Version":
            version = value.strip()
    return [Package(name, version, ecosystem="PyPI", path=path)] if name and version else []


def canonical_pypi(name: str) -> str:
    """PEP 503 normalisation, so PyYAML and pyyaml are the same package."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ── npm ──────────────────────────────────────────────────────────────

def _npm(path: str, data: bytes) -> list[Package]:
    doc = json.loads(data)
    if not isinstance(doc, dict):
        return []
    name, version = doc.get("name"), doc.get("version")
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        return []
    return [Package(name, version, ecosystem="npm", path=path)]


# ── Java ─────────────────────────────────────────────────────────────

def _java(path: str, data: bytes, depth: int = 0) -> list[Package]:
    out: list[Package] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties") and info.file_size <= MAX_METADATA:
                props = dict(
                    line.split("=", 1) for line in zf.read(info).decode("utf-8", "replace").splitlines()
                    if "=" in line and not line.startswith("#")
                )
                group, artifact, version = (props.get(k, "").strip() for k in ("groupId", "artifactId", "version"))
                if group and artifact and version:
                    out.append(Package(f"{group}:{artifact}", version, ecosystem="Maven", path=path))
            # Spring Boot and WAR files carry their dependencies as nested jars.
            elif depth == 0 and name.endswith(".jar") and info.file_size <= MAX_NESTED:
                out += _java(f"{path}!/{name}", zf.read(info), depth + 1)
    return out


# ── Go ───────────────────────────────────────────────────────────────

def _uvarint(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def go_buildinfo(path: str, data: bytes) -> list[Package]:
    """The Go version and module list a binary was built with, as `go version -m`
    shows them. Reads the Go 1.18+ format, where both strings are inline after
    the 32-byte header; older binaries store pointers and are skipped."""
    if not data.startswith(_ELF):
        return []
    at = data.find(_GO_MAGIC)
    if at < 0 or at + 32 > len(data):
        return []
    flags = data[at + 15]
    if not flags & 0x2:
        return []
    pos = at + 32
    n, pos = _uvarint(data, pos)
    version = data[pos:pos + n].decode("utf-8", "replace")
    pos += n
    n, pos = _uvarint(data, pos)
    modinfo = data[pos:pos + n].decode("utf-8", "replace")
    # modinfo is wrapped in 16-byte sentinels.
    if len(modinfo) >= 33 and modinfo[-17] == "\n":
        modinfo = modinfo[16:-16]

    out: list[Package] = []
    stdlib = _go_version(version)
    if stdlib:
        out.append(Package("stdlib", stdlib, ecosystem="Go", path=path))
    deps: list[Package] = []
    for line in modinfo.splitlines():
        parts = line.split("\t")
        if parts[0] == "dep" and len(parts) >= 3:
            deps.append(Package(parts[1], parts[2], ecosystem="Go", path=path))
        elif parts[0] == "=>" and len(parts) >= 3 and deps:
            # A replace directive swaps out the dep listed just before it.
            deps[-1] = Package(parts[1], parts[2], ecosystem="Go", path=path)
        elif parts[0] == "mod" and len(parts) >= 3 and parts[2] not in ("(devel)", ""):
            deps.append(Package(parts[1], parts[2], ecosystem="Go", path=path))
    return out + [d for d in deps if d.version and not d.version.startswith("(")]


def _go_version(version: str) -> str:
    """go1.22.5 → 1.22.5, go1.22 → 1.22.0. OSV misreads the go prefix."""
    m = re.match(r"go(\d+)\.(\d+)(?:\.(\d+))?", version.strip())
    if not m:
        return ""
    return f"{m.group(1)}.{m.group(2)}.{m.group(3) or 0}"

"""Read an image's filesystem layers for the facts Basely needs: the package
database, the distro, and whether a shell, package manager and libc are there.

Only the package databases and a handful of paths are read; everything else in
a layer streams past without being kept.
"""

from __future__ import annotations

import re
import tarfile
from dataclasses import dataclass, field
from typing import IO

from . import lang
from .model import Distro, Package

DPKG_STATUS = "var/lib/dpkg/status"
DPKG_STATUS_D = "var/lib/dpkg/status.d/"   # distroless and DHI: one file per package
APK_DBS = ("lib/apk/db/installed", "usr/lib/apk/db/installed")  # Wolfi uses usr/lib
OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
APK_REPOSITORIES = "etc/apk/repositories"

_SHELLS = {"bin/sh", "usr/bin/sh", "bin/bash", "usr/bin/bash", "bin/ash", "bin/busybox", "usr/bin/busybox"}
_PACKAGE_MANAGERS = {
    "usr/bin/apt-get": "apt", "bin/apt-get": "apt",
    "sbin/apk": "apk", "usr/sbin/apk": "apk", "usr/bin/apk": "apk", "bin/apk": "apk",
    "usr/bin/microdnf": "microdnf", "usr/bin/dnf": "dnf", "usr/bin/yum": "yum",
}
_MUSL_LOADER = re.compile(r"(usr/)?lib/ld-musl-[\w-]+\.so\.1")
_GLIBC_LOADER = re.compile(r"(usr/)?lib(64|32|/[\w-]+-linux-gnu)?/ld-linux[\w.-]*\.so\.\d")

_WANTED = {DPKG_STATUS, APK_REPOSITORIES, *APK_DBS, *OS_RELEASE}


@dataclass
class LayerScan:
    """What one layer contributes. Layers are scanned in parallel, then merged
    in order so a later layer's file replaces an earlier one's."""
    files: dict[str, str] = field(default_factory=dict)
    paths: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    opaque: set[str] = field(default_factory=set)
    lang: dict[str, list[Package]] = field(default_factory=dict)


def scan_layer(fileobj: IO[bytes], mode: str = "r|*", languages: bool = True) -> LayerScan:
    scan = LayerScan()
    with tarfile.open(fileobj=fileobj, mode=mode) as tf:
        for member in tf:
            path = _clean(member.name)
            base = path.rsplit("/", 1)[-1]
            if base == ".wh..wh..opq":
                scan.opaque.add(path[: -len(base)])
                continue
            if base.startswith(".wh."):
                scan.removed.add(path[: -len(base)] + base[4:])
                continue
            if member.isdir():
                continue
            scan.paths.add(path)
            if (path in _WANTED or path.startswith(DPKG_STATUS_D)) and member.isfile():
                data = tf.extractfile(member)
                if data is not None:
                    scan.files[path] = data.read().decode("utf-8", "replace")
            elif languages and member.isfile():
                finder = lang.kind(path, member.size, bool(member.mode & 0o111))
                if finder:
                    data = tf.extractfile(member)
                    if data is not None:
                        found = lang.parse(finder, path, data.read())
                        if found:
                            scan.lang[path] = found
    return scan


def _clean(name: str) -> str:
    return re.sub(r"^(\./|/)+", "", name)


@dataclass
class Filesystem:
    files: dict[str, str] = field(default_factory=dict)
    paths: set[str] = field(default_factory=set)
    lang: dict[str, list[Package]] = field(default_factory=dict)


def merge(scans: list[LayerScan]) -> Filesystem:
    fs = Filesystem()
    for scan in scans:
        gone = [lambda p, prefix=prefix: p.startswith(prefix) for prefix in scan.opaque]
        gone += [lambda p, path=path: p == path or p.startswith(path + "/") for path in scan.removed]
        if gone:
            fs.files = {k: v for k, v in fs.files.items() if not any(g(k) for g in gone)}
            fs.paths = {p for p in fs.paths if not any(g(p) for g in gone)}
            fs.lang = {k: v for k, v in fs.lang.items() if not any(g(k) for g in gone)}
        fs.files.update(scan.files)
        fs.paths |= scan.paths
        fs.lang.update(scan.lang)
    return fs


# ── Package databases ────────────────────────────────────────────────

def _stanzas(text: str) -> list[dict[str, str]]:
    out = []
    for block in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        key = ""
        for line in block.splitlines():
            if line[:1] in (" ", "\t"):
                continue  # continuation lines (Description, Conffiles) aren't needed
            key, sep, value = line.partition(":")
            if sep:
                fields[key.strip()] = value.strip()
        if fields:
            out.append(fields)
    return out


def parse_dpkg(text: str) -> list[Package]:
    pkgs = []
    for f in _stanzas(text):
        if "Package" not in f or "Version" not in f:
            continue
        status = f.get("Status", "install ok installed")
        if not status.endswith(" installed"):
            continue
        # "Source: glibc (2.36-9+deb12u4)" carries the source version when it
        # differs from the binary's, e.g. after a binNMU (+b1).
        source, source_version = f.get("Source", ""), ""
        m = re.fullmatch(r"(\S+)\s+\((\S+)\)", source)
        if m:
            source, source_version = m.groups()
        elif source:
            source_version = re.sub(r"\+b\d+$", "", f["Version"])
        pkgs.append(Package(f["Package"], f["Version"], source, source_version))
    return pkgs


def parse_apk(text: str) -> list[Package]:
    pkgs = []
    for block in re.split(r"\n\s*\n", text):
        fields = dict(re.findall(r"^([A-Za-z]):(.*)$", block, re.M))
        if "P" in fields and "V" in fields:
            pkgs.append(Package(fields["P"], fields["V"], fields.get("o", ""), fields["V"] if "o" in fields else ""))
    return pkgs


def apk_owned(text: str) -> set[str]:
    """Every file path the apk database says a package installed."""
    owned: set[str] = set()
    folder = ""
    for line in text.splitlines():
        if line.startswith("F:"):
            folder = line[2:]
        elif line.startswith("R:"):
            owned.add(f"{folder}/{line[2:]}" if folder else line[2:])
    return owned


def parse_os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip().strip("'\"")
    return out


# ── Putting it together ──────────────────────────────────────────────

@dataclass
class Contents:
    distro: Distro
    packages: list[Package]
    shell: bool
    package_manager: str
    libc: str


def read(fs: Filesystem) -> Contents:
    packages: list[Package] = []
    if DPKG_STATUS in fs.files:
        packages += parse_dpkg(fs.files[DPKG_STATUS])
    for path in sorted(fs.files):
        if path.startswith(DPKG_STATUS_D) and not path.endswith(".md5sums"):
            packages += parse_dpkg(fs.files[path])
    owned: set[str] = set()
    for path in APK_DBS:
        if path in fs.files:
            packages += parse_apk(fs.files[path])
            owned |= apk_owned(fs.files[path])

    return Contents(
        distro=_distro(fs),
        packages=_dedupe(packages) + _language(fs, owned),
        shell=bool(_SHELLS & fs.paths),
        package_manager=next((pm for path, pm in _PACKAGE_MANAGERS.items() if path in fs.paths), ""),
        libc=_libc(fs, packages),
    )


def _language(fs: Filesystem, owned: set[str]) -> list[Package]:
    """Language packages, minus those the distro installed: its own advisories
    already cover them. Debian's dist-packages are never scanned for the same
    reason; apk installs into site-packages, so apk's file list decides."""
    seen: dict[tuple[str, str, str], Package] = {}
    for path in sorted(fs.lang):
        if path.split("!/")[0] in owned:
            continue
        for p in fs.lang[path]:
            seen.setdefault((p.ecosystem, p.name, p.version), p)
    return sorted(seen.values(), key=lambda p: (p.ecosystem, p.name, p.version))


def _dedupe(packages: list[Package]) -> list[Package]:
    seen: dict[str, Package] = {}
    for p in packages:
        seen[p.name] = p
    return sorted(seen.values(), key=lambda p: p.name)


def _distro(fs: Filesystem) -> Distro:
    text = next((fs.files[p] for p in OS_RELEASE if p in fs.files), "")
    info = parse_os_release(text)
    distro_id = info.get("ID", "").lower()
    repos = fs.files.get(APK_REPOSITORIES, "")
    if not distro_id and any(p in fs.files for p in APK_DBS):
        # Chainguard images can ship without os-release; their apk
        # repositories say which advisory feed applies.
        distro_id = "chainguard" if "apk.cgr.dev" in repos else "wolfi" if "wolfi" in repos or "cgr.dev" in repos else ""
    elif distro_id == "wolfi" and "apk.cgr.dev" in repos:
        distro_id = "chainguard"
    return Distro(
        id=distro_id,
        version_id=info.get("VERSION_ID", ""),
        name=info.get("PRETTY_NAME", ""),
        lts="LTS" in info.get("VERSION", ""),
    )


def _libc(fs: Filesystem, packages: list[Package]) -> str:
    names = {p.name for p in packages}
    if "musl" in names and "glibc" not in names:
        return "musl"
    if names & {"libc6", "glibc", "libc-bin"}:
        return "glibc"
    if any(_MUSL_LOADER.fullmatch(p) for p in fs.paths):
        return "musl"
    if any(_GLIBC_LOADER.fullmatch(p) for p in fs.paths):
        return "glibc"
    return ""

"""Builders for the synthetic images, layers and OSV records the tests use."""

from __future__ import annotations

import io
import tarfile

from basely.model import Distro, Image, Package, Vuln


def layer(files: dict[str, str | None], links: dict[str, str] | None = None, gzip: bool = True) -> bytes:
    """A layer tarball. A None value makes an empty file (useful for /bin/sh)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gzip else "w") as tf:
        for path, content in files.items():
            data = (content or "").encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for path, target in (links or {}).items():
            info = tarfile.TarInfo(path)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


def image(ref: str = "python:3.12", *, size: int = 50_000_000, distro: str = "debian", version_id: str = "13",
          shell: bool = True, pm: str = "apt", libc: str = "glibc", user: str = "", env: dict | None = None,
          vulns: list[Vuln] | None = None, scanned: bool = True, platforms: list[str] | None = None,
          created: str = "", packages: list[Package] | None = None) -> Image:
    return Image(
        ref=ref, size=size, distro=Distro(distro, version_id), shell=shell, package_manager=pm, libc=libc,
        user=user, env=env if env is not None else {"PYTHON_VERSION": "3.12.7"}, vulns=vulns or [],
        scanned=scanned, platforms=platforms or ["linux/amd64", "linux/arm64"], created=created,
        packages=packages or [Package("libc6", "2.41-12", "glibc", "2.41-12")],
    )


def vulns(critical: int = 0, high: int = 0, medium: int = 0, fixable: int = 0) -> list[Vuln]:
    out = []
    for sev, n in (("critical", critical), ("high", high), ("medium", medium)):
        for i in range(n):
            out.append(Vuln(f"CVE-{sev}-{i}", f"X-{sev}-{i}", "pkg", "1", sev))
    for v in out[:fixable]:
        v.status = "fixable"
    return out


def record(vid: str, ecosystem: str, name: str, fixed: str = "", severity: list | None = None,
           spec: dict | None = None, upstream: list[str] | None = None, other: list[dict] | None = None) -> dict:
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    affected = [{"package": {"ecosystem": ecosystem, "name": name},
                 "ranges": [{"type": "ECOSYSTEM", "events": events}],
                 "ecosystem_specific": spec or {}}]
    rec = {"id": vid, "affected": affected + (other or []), "severity": severity or []}
    if upstream:
        rec["upstream"] = upstream
    return rec

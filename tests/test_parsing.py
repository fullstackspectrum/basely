"""Image references, Dockerfiles, package databases and image layers."""

import io

import pytest

from basely import dockerfile, packages
from basely.errors import BaselyError
from basely.refs import parse
from helpers import layer

# ── Image references ─────────────────────────────────────────────────


@pytest.mark.parametrize("text, host, repo, tag, shown", [
    ("python", "docker.io", "library/python", "latest", "python:latest"),
    ("python:3.12-slim", "docker.io", "library/python", "3.12-slim", "python:3.12-slim"),
    ("bitnami/redis:7", "docker.io", "bitnami/redis", "7", "bitnami/redis:7"),
    ("docker.io/library/node:22", "docker.io", "library/node", "22", "node:22"),
    ("index.docker.io/library/node", "docker.io", "library/node", "latest", "node:latest"),
    ("dhi.io/python:3.12-dev", "dhi.io", "python", "3.12-dev", "dhi.io/python:3.12-dev"),
    ("cgr.dev/chainguard/python:latest", "cgr.dev", "chainguard/python", "latest", "cgr.dev/chainguard/python:latest"),
    ("localhost:5000/team/app:1.0", "localhost:5000", "team/app", "1.0", "localhost:5000/team/app:1.0"),
])
def test_parse_refs(text, host, repo, tag, shown):
    ref = parse(text)
    assert (ref.host, ref.repo, ref.tag, str(ref)) == (host, repo, tag, shown)


def test_parse_digest_and_api_host():
    ref = parse("python@sha256:" + "a" * 64)
    assert ref.reference == "sha256:" + "a" * 64
    assert ref.api_host == "registry-1.docker.io"
    assert str(ref) == "python@sha256:" + "a" * 64


@pytest.mark.parametrize("bad", ["Python:3", "python:bad tag", "python@sha256:xyz", "-x"])
def test_parse_rejects_bad_refs(bad):
    with pytest.raises(BaselyError):
        parse(bad)


# ── Dockerfiles ──────────────────────────────────────────────────────

MULTI = """\
# syntax=docker/dockerfile:1
ARG PY=3.12
ARG VARIANT
FROM --platform=$BUILDPLATFORM python:${PY}${VARIANT:-} AS build
RUN --mount=type=cache,target=/root/.cache \\
    apt-get update && \\
    # a comment inside a continuation
    apt-get install -y gcc
USER root
FROM build AS test
RUN pytest
FROM python:${PY}-slim
COPY --from=build /app /app
USER 10001
CMD ["python", "/app/main.py"]
"""


def test_dockerfile_stages():
    stages = dockerfile.parse(MULTI)
    assert [s.image for s in stages] == ["python:3.12", "build", "python:3.12-slim"]
    build, test, final = stages
    assert build.name == "build" and build.line == 4 and build.platform == "$BUILDPLATFORM"
    assert build.role == "build" and build.needs_shell and build.package_manager == "apt"
    assert build.switches_to_root
    assert test.parent == "build" and not test.is_image
    assert final.final and final.role == "runtime" and not final.needs_shell and final.users == ["10001"]


def test_dockerfile_final_stage_with_run_is_build_role():
    (stage,) = dockerfile.parse("FROM alpine:3.22\nRUN apk add --no-cache curl\n")
    assert stage.final and stage.role == "build" and stage.package_manager == "apk"


def test_dockerfile_exec_form_run_needs_no_shell():
    (stage,) = dockerfile.parse('FROM gcr.io/distroless/static\nRUN ["/healthcheck"]\n')
    assert not stage.needs_shell


def test_dockerfile_scratch_and_errors():
    (stage,) = dockerfile.parse("FROM scratch\nCOPY app /app\n")
    assert not stage.is_image
    with pytest.raises(BaselyError):
        dockerfile.parse("RUN echo hi\n")


def test_dockerfile_arg_defaults():
    stages = dockerfile.parse("ARG BASE=node\nARG TAG\nFROM ${BASE}:${TAG:-22}-slim\n")
    assert stages[0].image == "node:22-slim"


# ── Package databases ────────────────────────────────────────────────

DPKG = """\
Package: libc6
Status: install ok installed
Version: 2.41-12
Source: glibc
Description: GNU C Library
 continuation line

Package: libacl1
Status: install ok installed
Version: 2.3.2-2+b1
Source: acl

Package: bsdutils
Status: install ok installed
Version: 1:2.41-5
Source: util-linux (2.41-5)

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0
"""


def test_parse_dpkg_source_versions():
    pkgs = {p.name: p for p in packages.parse_dpkg(DPKG)}
    assert set(pkgs) == {"libc6", "libacl1", "bsdutils"}
    assert (pkgs["libc6"].osv_name, pkgs["libc6"].osv_version) == ("glibc", "2.41-12")
    # A binNMU suffix belongs to the binary, not the source.
    assert pkgs["libacl1"].osv_version == "2.3.2-2"
    assert (pkgs["bsdutils"].osv_name, pkgs["bsdutils"].osv_version) == ("util-linux", "2.41-5")


def test_parse_apk():
    text = "C:Q1abc\nP:libssl3\nV:3.5.9-r0\no:openssl\n\nP:busybox\nV:1.37.0-r31\n"
    pkgs = {p.name: p for p in packages.parse_apk(text)}
    assert pkgs["libssl3"].osv_name == "openssl" and pkgs["libssl3"].osv_version == "3.5.9-r0"
    assert pkgs["busybox"].osv_name == "busybox"


def _fs(*layers: bytes) -> packages.Filesystem:
    return packages.merge([packages.scan_layer(io.BytesIO(raw)) for raw in layers])


def test_scan_debian_image():
    base = layer({
        "usr/lib/os-release": 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n',
        "var/lib/dpkg/status": DPKG,
        "usr/bin/sh": None, "usr/bin/apt-get": None,
    }, links={"etc/os-release": "../usr/lib/os-release"})
    c = packages.read(_fs(base))
    assert c.distro.ecosystem == "Debian:13"
    assert c.shell and c.package_manager == "apt" and c.libc == "glibc"
    assert len(c.packages) == 3


def test_scan_distroless_status_d_and_whiteouts():
    base = layer({
        "etc/os-release": "ID=debian\nVERSION_ID=12\n",
        "var/lib/dpkg/status.d/libc6": DPKG.split("\n\n")[0] + "\n",
        "var/lib/dpkg/status.d/libc6.md5sums": "abc  lib/x\n",
        "var/lib/dpkg/status.d/tzdata": "Package: tzdata\nVersion: 2025b-0\n",
        "bin/sh": None,
    })
    # A later layer deletes the shell and tzdata.
    top = layer({"bin/.wh.sh": None, "var/lib/dpkg/status.d/.wh.tzdata": None})
    c = packages.read(_fs(base, top))
    assert [p.name for p in c.packages] == ["libc6"]
    assert not c.shell and c.package_manager == ""


def test_scan_alpine_and_chainguard():
    alpine = layer({"etc/os-release": "ID=alpine\nVERSION_ID=3.22.1\n",
                    "lib/apk/db/installed": "P:musl\nV:1.2.5-r10\n", "sbin/apk": None, "bin/busybox": None})
    c = packages.read(_fs(alpine))
    assert c.distro.ecosystem == "Alpine:v3.22" and c.libc == "musl" and c.package_manager == "apk"

    # Chainguard images can have no os-release; the apk repositories identify them.
    cg = layer({"usr/lib/apk/db/installed": "P:glibc\nV:2.44-r21\n\nP:ld-linux\nV:2.44-r21\no:glibc\n",
                "etc/apk/repositories": "https://apk.cgr.dev/chainguard\n"})
    c = packages.read(_fs(cg))
    assert c.distro.ecosystem == "Chainguard" and c.libc == "glibc" and not c.shell


def test_scan_libc_from_loader_when_no_packages():
    c = packages.read(_fs(layer({"lib/ld-musl-x86_64.so.1": None})))
    assert c.libc == "musl"
    c = packages.read(_fs(layer({"lib64/ld-linux-x86-64.so.2": None})))
    assert c.libc == "glibc"


def test_opaque_whiteout_clears_directory():
    base = layer({"var/lib/dpkg/status.d/a": "Package: a\nVersion: 1\n"})
    top = layer({"var/lib/dpkg/status.d/.wh..wh..opq": None, "var/lib/dpkg/status.d/b": "Package: b\nVersion: 1\n"})
    assert [p.name for p in packages.read(_fs(base, top)).packages] == ["b"]

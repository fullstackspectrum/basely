"""CVSS 4.0 scoring, language packages and VEX."""

import base64
import io
import json
import zipfile
from pathlib import Path

import pytest

from basely import cvss, dockerfile, lang, packages, vex
from basely.advise import Advisor
from basely.errors import BaselyError
from basely.model import Image, Package, Vuln
from helpers import image, layer, vulns
from test_advise import FakeOSV, FakeRegistry

FIXTURES = Path(__file__).parent / "fixtures"

# ── CVSS 4.0 ─────────────────────────────────────────────────────────

GITHUB_V4 = json.loads((FIXTURES / "cvss4_github.json").read_text())["vectors"]


@pytest.mark.parametrize("case", GITHUB_V4, ids=[c["advisory"] for c in GITHUB_V4])
def test_cvss4_matches_github(case):
    assert cvss.base_score_v4(case["vector"]) == case["score"]


@pytest.mark.parametrize("vector, score", [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    # Threat metric: unproven exploitation moves it to MacroVector 000220,
    # which FIRST's table scores 8.1, and it's that MacroVector's worst case.
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1),
])
def test_cvss4_reference_points(vector, score):
    assert cvss.base_score_v4(vector) == score
    assert cvss.score(vector) == score


@pytest.mark.parametrize("bad", [
    "CVSS:4.0/AV:N/AC:L",                                            # missing metrics
    "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # bad value
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:Z",
    "not a vector",
])
def test_cvss4_rejects_garbage(bad):
    assert cvss.base_score_v4(bad) is None


# ── Language packages ────────────────────────────────────────────────

def _jar(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _go_binary(version: str, mod_lines: list[str]) -> bytes:
    def uvarint(n: int) -> bytes:
        out = b""
        while n >= 0x80:
            out += bytes([n & 0x7F | 0x80])
            n >>= 7
        return out + bytes([n])
    mod = ("0" * 16 + "".join(line + "\n" for line in mod_lines) + "1" * 16).encode()
    header = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16
    body = uvarint(len(version)) + version.encode() + uvarint(len(mod)) + mod
    return b"\x7fELF" + b"\x00" * 5000 + header + body + b"\x00" * 100


def test_python_metadata_and_egg_info():
    meta = b"Metadata-Version: 2.1\nName: PyYAML\nVersion: 6.0.1\n\nName: not-a-header\n"
    assert lang.parse("python", "x/site-packages/PyYAML-6.0.1.dist-info/METADATA", meta) == [
        Package("PyYAML", "6.0.1", ecosystem="PyPI", path="x/site-packages/PyYAML-6.0.1.dist-info/METADATA")]
    assert lang.kind("usr/lib/python3/site-packages/six.egg-info/PKG-INFO", 100, False) == "python"
    # Debian's own Python packages live in dist-packages; dpkg covers them.
    assert lang.kind("usr/lib/python3/dist-packages/six-1.16.dist-info/METADATA", 100, False) == ""


def test_npm_package_json():
    path = "usr/local/lib/node_modules/npm/node_modules/@sigstore/core/package.json"
    assert lang.kind(path, 500, False) == "npm"
    assert lang.parse("npm", path, b'{"name": "@sigstore/core", "version": "2.0.0"}')[0].name == "@sigstore/core"
    assert lang.parse("npm", path, b"not json") == []
    assert lang.parse("npm", path, b'{"name": "x"}') == []
    # A package.json that isn't a package directly under node_modules is skipped.
    assert lang.kind("usr/local/lib/node_modules/npm/docs/package.json", 500, False) == ""


def test_gemspec_filename():
    path = "usr/local/bundle/specifications/nokogiri-1.15.4-x86_64-linux.gemspec"
    (pkg,) = lang.parse("gem", path, b"")
    assert (pkg.name, pkg.version, pkg.ecosystem) == ("nokogiri", "1.15.4", "RubyGems")


def test_jar_with_nested_jars():
    pom = b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"
    inner = _jar({"META-INF/maven/com.fasterxml/jackson-databind/pom.properties":
                  b"groupId=com.fasterxml.jackson.core\nartifactId=jackson-databind\nversion=2.9.0\n"})
    outer = _jar({"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": pom,
                  "BOOT-INF/lib/jackson-databind-2.9.0.jar": inner})
    found = {p.name: p for p in lang.parse("java", "app/app.jar", outer)}
    assert found["org.apache.logging.log4j:log4j-core"].version == "2.14.1"
    assert found["com.fasterxml.jackson.core:jackson-databind"].path == "app/app.jar!/BOOT-INF/lib/jackson-databind-2.9.0.jar"
    assert lang.parse("java", "app/broken.jar", b"PK not really") == []


def test_go_buildinfo():
    binary = _go_binary("go1.22.5", [
        "path\texample.com/app",
        "mod\texample.com/app\t(devel)\t",
        "dep\tgolang.org/x/net\tv0.17.0\th1:abc=",
        "dep\tgithub.com/old/thing\tv1.0.0\th1:def=",
        "=>\tgithub.com/new/thing\tv1.2.0\th1:ghi=",
    ])
    found = {(p.name, p.version) for p in lang.go_buildinfo("usr/local/bin/app", binary)}
    assert found == {("stdlib", "1.22.5"), ("golang.org/x/net", "v0.17.0"), ("github.com/new/thing", "v1.2.0")}
    assert {(p.name, p.version) for p in lang.go_buildinfo("bin/go", _go_binary("go1.23", []))} == {("stdlib", "1.23.0")}
    assert lang.go_buildinfo("bin/sh", b"\x7fELF" + b"\x00" * 9000) == []
    assert lang.go_buildinfo("x", b"MZ not elf") == []


def test_scan_finds_language_packages_but_not_distro_owned_ones():
    meta = b"Name: pip\nVersion: 24.0\n\n"
    apk_db = ("P:py3-pip\nV:24.0-r1\nF:usr/lib/python3.12/site-packages/pip-24.0.dist-info\nR:METADATA\n\n"
              "P:musl\nV:1.2.5-r0\n")
    base = layer({
        "etc/os-release": "ID=alpine\nVERSION_ID=3.22.0\n",
        "lib/apk/db/installed": apk_db,
        "usr/lib/python3.12/site-packages/pip-24.0.dist-info/METADATA": meta.decode(),
        "usr/local/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA": "Name: requests\nVersion: 2.31.0\n",
        "usr/local/lib/python3.12/site-packages/gone-1.0.dist-info/METADATA": "Name: gone\nVersion: 1.0\n",
    })
    top = layer({"usr/local/lib/python3.12/site-packages/.wh.gone-1.0.dist-info": None})
    fs = packages.merge([packages.scan_layer(io.BytesIO(raw)) for raw in (base, top)])
    c = packages.read(fs)
    lang_pkgs = [(p.ecosystem, p.name) for p in c.packages if p.ecosystem]
    assert lang_pkgs == [("PyPI", "requests")]


def test_scan_go_binary_through_a_layer():
    raw = io.BytesIO()
    import tarfile
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        data = _go_binary("go1.25.3", [])
        info = tarfile.TarInfo("usr/local/bin/tool")
        info.size, info.mode = len(data), 0o755
        tf.addfile(info, io.BytesIO(data))
        # Not executable, so not read.
        info2 = tarfile.TarInfo("usr/local/bin/data.bin")
        info2.size, info2.mode = len(data), 0o644
        tf.addfile(info2, io.BytesIO(data))
    scan = packages.scan_layer(io.BytesIO(raw.getvalue()))
    assert list(scan.lang) == ["usr/local/bin/tool"]
    assert packages.scan_layer(io.BytesIO(raw.getvalue()), languages=False).lang == {}


# ── VEX ──────────────────────────────────────────────────────────────

OPENVEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "statements": [
        {"vulnerability": {"name": "CVE-2024-1"}, "status": "not_affected",
         "justification": "vulnerable_code_not_in_execute_path",
         "products": [{"@id": "pkg:deb/debian/openssl@3.5.1?arch=amd64",
                       "subcomponents": [{"@id": "pkg:deb/debian/libssl3@3.5.1"}]}]},
        {"vulnerability": {"name": "CVE-2024-2", "aliases": ["GHSA-zzzz-zzzz-zzzz"]}, "status": "under_investigation",
         "products": [{"@id": "pkg:oci/python@sha256%3Aabc"}]},
        {"vulnerability": {"name": "CVE-2024-3"}, "status": "not_affected",
         "products": [{"@id": "pkg:deb/debian/zlib@1.3"}]},
        {"vulnerability": {"name": "CVE-2024-4"}, "status": "affected", "products": ["pkg:pypi/pip@23.0"]},
        {"vulnerability": {"name": "CVE-2024-4"}, "status": "fixed", "products": ["pkg:pypi/pip@23.0"]},
    ],
}


def _vex_image():
    vs = [Vuln("CVE-2024-1", "DEBIAN-CVE-2024-1", "openssl", "3.5.1", "high"),
          Vuln("CVE-2024-2", "DEBIAN-CVE-2024-2", "glibc", "2.41", "medium"),
          Vuln("CVE-2024-3", "DEBIAN-CVE-2024-3", "openssl", "3.5.1", "low"),   # statement is for zlib
          Vuln("CVE-2024-4", "GHSA-x", "pip", "23.0", "high", ecosystem="PyPI"),
          Vuln("CVE-2024-5", "DEBIAN-CVE-2024-5", "openssl", "3.5.1", "critical")]
    return Image(ref="x", vulns=vs, scanned=True)


@pytest.mark.parametrize("wrap", ["raw", "intoto", "dsse"])
def test_vex_parse_and_apply(wrap):
    doc = OPENVEX
    if wrap in ("intoto", "dsse"):
        doc = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://openvex.dev/ns/v0.2.0",
               "subject": [], "predicate": OPENVEX}
    if wrap == "dsse":
        doc = {"payloadType": "application/vnd.in-toto+json",
               "payload": base64.b64encode(json.dumps(doc).encode()).decode(), "signatures": []}
    img = _vex_image()
    removed = vex.apply(img, vex.parse(doc), "the image's own VEX")
    left = {v.id: v for v in img.vulns}
    # 1: not affected. 4: affected, then fixed; the later statement wins.
    assert removed == 2 and set(left) == {"CVE-2024-2", "CVE-2024-3", "CVE-2024-5"}
    assert left["CVE-2024-2"].status == "investigating"   # image-level statement, no package filter
    assert img.vex_suppressed == 2 and img.vex_sources == ["the image's own VEX"]


def test_purl_names():
    assert vex._purl_name("pkg:npm/%40babel/core@7.0.0") == "@babel/core"
    assert vex._purl_name("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") == "org.apache.logging.log4j:log4j-core"
    assert vex._purl_name("pkg:golang/golang.org/x/net@v0.17.0") == "golang.org/x/net"
    assert vex._purl_name("pkg:oci/python@sha256%3Aabc") == ""
    assert vex._purl_name("https://example.com") == ""


def test_vex_load_file(tmp_path):
    good = tmp_path / "vex.json"
    good.write_text(json.dumps(OPENVEX))
    assert len(vex.load_file(str(good))) == 5
    (tmp_path / "empty.json").write_text("{}")
    with pytest.raises(BaselyError, match="no OpenVEX statements"):
        vex.load_file(str(tmp_path / "empty.json"))
    with pytest.raises(BaselyError, match="can't read"):
        vex.load_file(str(tmp_path / "missing.json"))


class VexRegistry(FakeRegistry):
    """A registry that serves one OpenVEX attestation for one manifest."""

    def __init__(self, images, digest, doc):
        super().__init__(images)
        self.digest, self.doc = digest, doc

    def referrers(self, ref, digest):
        if digest != self.digest:
            return []
        return [{"digest": "sha256:att", "artifactType": "application/vnd.in-toto+json",
                 "annotations": {"in-toto.io/predicate-type": "https://openvex.dev/ns/v0.2.0"}},
                {"digest": "sha256:sbom", "annotations": {"in-toto.io/predicate-type": "https://spdx.dev/Document"}}]

    def manifest(self, ref, reference=None):
        assert reference == "sha256:att"
        return {"layers": [{"digest": "sha256:layer"}]}, reference

    def blob(self, ref, digest, limit=16_000_000):
        return json.dumps({"predicate": self.doc}).encode()


def test_advisor_applies_vendor_and_user_vex():
    hardened = image("dhi.io/python:3.12", shell=False, pm="", user="65532",
                     vulns=[Vuln("CVE-2024-1", "D-1", "openssl", "3.5.1", "critical")] + vulns(high=1))
    hardened.manifest_digest = "sha256:hardened"
    images = {"python:3.12-slim": image("python:3.12-slim", vulns=vulns(critical=1, high=3)),
              "dhi.io/python:3.12": hardened}
    user = vex.parse({"statements": [{"vulnerability": {"name": "CVE-high-0"}, "status": "not_affected",
                                      "products": []}]})
    registry = VexRegistry(images, "sha256:hardened", OPENVEX)
    advice = Advisor(registry, FakeOSV(), include=("hardened",), user_vex=user).advise(
        dockerfile.parse("FROM python:3.12-slim\n"))
    (sa,) = advice.stages
    pick = sa.candidates[0]
    assert pick.ref == "dhi.io/python:3.12"
    # The vendor's VEX removes CVE-2024-1; the user's removes CVE-high-0 everywhere.
    assert [v.id for v in pick.image.vulns] == []
    assert pick.image.vex_sources == ["the image's own VEX", "your VEX"]
    assert any(i.level == "good" and "rules out 2 advisories" in i.text for i in pick.issues)
    assert sa.current.image.vex_suppressed == 1


def test_advisor_can_skip_vendor_vex():
    hardened = image("dhi.io/python:3.12", vulns=[Vuln("CVE-2024-1", "D-1", "openssl", "3.5.1", "critical")])
    hardened.manifest_digest = "sha256:hardened"
    registry = VexRegistry({"dhi.io/python:3.12": hardened}, "sha256:hardened", OPENVEX)
    advice = Advisor(registry, FakeOSV(), include=(), vendor_vex=False).advise(
        dockerfile.parse("FROM dhi.io/python:3.12\n"))
    assert advice.stages[0].current.image.count() == 1

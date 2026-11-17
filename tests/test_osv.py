"""CVSS scoring and classifying OSV advisories."""

import pytest

from basely import cvss
from basely.model import Distro, Image, Package
from basely.osv import classify
from helpers import record


@pytest.mark.parametrize("vector, score, severity", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "high"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.6, "medium"),
    ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "unknown"),
])
def test_cvss3(vector, score, severity):
    assert cvss.base_score(vector) == score
    assert cvss.severity(cvss.base_score(vector)) == severity


def test_cvss_rejects_v4_and_garbage():
    assert cvss.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss.base_score("CVSS:3.1/AV:X") is None


HIGH = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
CRIT = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
V4 = [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]


def _image(eco_id="debian", version="13"):
    return Image(ref="x", distro=Distro(eco_id, version))


def _run(img, pairs, records, upstream=None):
    classify(img, pairs, {r["id"]: r for r in records}, upstream or {})
    return {v.id: v for v in img.vulns}


def test_fix_is_scoped_to_the_images_release():
    openssl = Package("libssl3", "3.5.1-1", "openssl", "3.5.1-1")
    rec = record("DEBIAN-CVE-2025-1", "Debian:13", "openssl", severity=HIGH,
                 other=[{"package": {"ecosystem": "Debian:12", "name": "openssl"},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.9"}]}]}])
    found = _run(_image(), [(openssl, ["DEBIAN-CVE-2025-1"])], [rec])
    # Debian 12 has a fix; Debian 13, which this image is, doesn't.
    assert found["CVE-2025-1"].status == "unfixed"
    assert found["CVE-2025-1"].severity == "high"


def test_fixable_and_ignored_and_deduped():
    glibc = Package("libc6", "2.41-1", "glibc", "2.41-1")
    zlib = Package("zlib1g", "1.3-1", "zlib", "1.3-1")
    records = [
        record("DEBIAN-CVE-2025-2", "Debian:13", "glibc", fixed="2.41-2", severity=CRIT),
        record("DEBIAN-CVE-2005-9", "Debian:13", "glibc", spec={"urgency": "unimportant"}),
        # The same CVE through a second package keeps the worst view of it.
        record("DEBIAN-CVE-2025-2b", "Debian:13", "zlib", severity=HIGH, upstream=["CVE-2025-2"]),
    ]
    img = _image()
    found = _run(img, [(glibc, ["DEBIAN-CVE-2025-2", "DEBIAN-CVE-2005-9"]), (zlib, ["DEBIAN-CVE-2025-2b"])], records)
    assert list(found) == ["CVE-2025-2"]
    assert found["CVE-2025-2"].status == "fixable" and found["CVE-2025-2"].fixed_version == "2.41-2"
    assert found["CVE-2025-2"].severity == "critical"
    assert img.ignored == 1 and img.scanned


def test_kernel_advisories_are_ignored():
    headers = Package("linux-libc-dev", "6.1.190-1", "linux", "6.1.190-1")
    img = _image("debian", "12")
    found = _run(img, [(headers, ["DEBIAN-CVE-2024-1"])],
                 [record("DEBIAN-CVE-2024-1", "Debian:12", "linux", fixed="6.1.192-1", severity=CRIT)])
    assert found == {} and img.ignored == 1


def test_chainguard_statuses():
    expat = Package("libexpat1", "2.10.0-r1", "expat", "2.10.0-r1")
    img = _image("chainguard", "")
    comp = lambda status: {"components": [{"latest_event_status": status}]}  # noqa: E731
    records = [
        record("CGA-1", "Chainguard", "expat", spec=comp("detection"), upstream=["CVE-2026-1"]),
        record("CGA-2", "Chainguard", "expat", spec=comp("pending_upstream_fix"), upstream=["CVE-2026-2"]),
        record("CGA-3", "Chainguard", "expat", spec=comp("false_positive_determination"), upstream=["CVE-2026-3"]),
    ]
    found = _run(img, [(expat, ["CGA-1", "CGA-2", "CGA-3"])], records)
    assert found["CVE-2026-1"].status == "investigating"
    assert found["CVE-2026-2"].status == "unfixed"
    assert "CVE-2026-3" not in found and img.ignored == 1


def test_ubuntu_priority_and_upstream_score():
    pkg = Package("libc6", "2.39-0ubuntu8.4", "glibc", "2.39-0ubuntu8.4")
    img = _image("ubuntu", "24.04")
    img.distro = Distro("ubuntu", "24.04", lts=True)
    records = [
        record("UBUNTU-CVE-2016-1", "Ubuntu:24.04:LTS", "glibc", severity=[{"type": "Ubuntu", "score": "negligible"}]),
        record("UBUNTU-CVE-2025-5", "Ubuntu:24.04:LTS", "glibc", severity=V4 + [{"type": "Ubuntu", "score": "medium"}]),
        record("UBUNTU-CVE-2025-6", "Ubuntu:24.04:LTS", "glibc", severity=V4),
    ]
    found = _run(img, [(pkg, ["UBUNTU-CVE-2016-1", "UBUNTU-CVE-2025-5", "UBUNTU-CVE-2025-6"])], records,
                 upstream={"CVE-2025-6": {"id": "CVE-2025-6", "severity": HIGH}})
    assert "CVE-2016-1" not in found
    # No 3.x vector: Ubuntu's own priority, then the upstream CVE's score.
    assert found["CVE-2025-5"].severity == "medium"
    assert found["CVE-2025-6"].severity == "high" and found["CVE-2025-6"].score == 7.5

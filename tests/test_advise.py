"""The catalogue, fit checks, recommendations and the Advisor flow, offline."""

import pytest

from basely import catalogue, dockerfile
from basely.advise import Advisor, Candidate, Issue, StageAdvice, _recommend, assess
from basely.errors import BaselyError
from basely.model import Package
from basely.refs import parse
from helpers import image, vulns

PYTHON = catalogue.family_for(parse("python:3.12"))


def test_family_lookup():
    assert catalogue.family_for(parse("dhi.io/python:3.12-dev")) is PYTHON
    assert catalogue.family_for(parse("cgr.dev/chainguard/jre")).key == "java"
    assert catalogue.family_for(parse("openjdk:17")).key == "java"
    assert catalogue.family_for(parse("gcr.io/distroless/python3-debian12")) is PYTHON
    assert catalogue.family_for(parse("gcr.io/distroless/java21-debian12")).key == "java"
    assert catalogue.family_for(parse("redis:7")) is None


def test_split_tag():
    assert catalogue.split_tag("3.12.7-slim-bookworm") == ("3.12.7", "slim-bookworm")
    assert catalogue.split_tag("latest") == ("", "latest")
    assert catalogue.split_tag("22") == ("22", "")


def test_runtime_version_from_env_and_packages():
    assert catalogue.runtime_version(PYTHON, image(env={"PYTHON_VERSION": "3.12.7"})) == "3.12.7"
    java = catalogue.family_for(parse("eclipse-temurin:21"))
    assert catalogue.runtime_version(java, image(env={"JAVA_VERSION": "jdk-21.0.5+11"})) == "21.0.5"
    wolfi = image(env={}, packages=[Package("python-3.15-base", "3.15.2_git20261113-r0")])
    assert catalogue.runtime_version(PYTHON, wolfi) == "3.15.2"
    debian = image(env={}, packages=[Package("python3.11-minimal", "3.11.2-6")])
    assert catalogue.runtime_version(PYTHON, debian) == "3.11.2"


def test_suggestions_follow_the_role():
    build = [s.ref for s in catalogue.suggestions(PYTHON, "3.12.7", "build")]
    runtime = [s.ref for s in catalogue.suggestions(PYTHON, "3.12.7", "runtime")]
    assert "dhi.io/python:3.12-dev" in build and "cgr.dev/chainguard/python:latest-dev" in build
    assert "dhi.io/python:3.12" in runtime and "python:3.12-slim" in runtime
    debian = catalogue.family_for(parse("debian:12"))
    assert "dhi.io/debian-base:bookworm" in [s.ref for s in catalogue.suggestions(debian, "12", "runtime")]


def test_next_versions():
    assert catalogue.next_version_candidates(PYTHON, "3.12.7")[:2] == ["3.13", "3.14"]
    node = catalogue.family_for(parse("node"))
    assert catalogue.next_version_candidates(node, "22")[:2] == ["24", "26"]
    assert catalogue.next_version_candidates(node, "23")[:1] == ["24"]
    java = catalogue.family_for(parse("eclipse-temurin"))
    assert catalogue.next_version_candidates(java, "17") == ["21", "25", "29"]


# ── Fit checks ───────────────────────────────────────────────────────

def _stage(text: str) -> dockerfile.Stage:
    return dockerfile.parse(text)[-1]


def _issues(stage, current, cand_img, source="official"):
    c = Candidate(cand_img.ref, source, cand_img)
    return {(i.level, i.text.split(",")[0].split(":")[0]) for i in assess(stage, PYTHON, current, c)}


def test_assess_breaking_and_cautions():
    stage = _stage("FROM python:3.12\nRUN apt-get update && apt-get install -y gcc\n")
    current = image()
    alpine = image("python:3.12-alpine", distro="alpine", pm="apk", libc="musl")
    issues = _issues(stage, current, alpine)
    assert ("breaking", "RUN installs packages with apt") in issues
    assert ("caution", "musl instead of glibc") in issues

    distroless = image("dhi.io/python:3.12", shell=False, pm="", user="65532")
    issues = _issues(stage, current, distroless, "hardened")
    assert ("breaking", "no shell") in issues
    assert ("caution", "runs as user 65532") in issues

    newer = image("python:3.14-slim", env={"PYTHON_VERSION": "3.14.0"}, platforms=["linux/amd64"])
    issues = _issues(stage, current, newer, "upgrade")
    assert ("caution", "Python 3.14 instead of 3.12") in issues
    assert ("caution", "no linux/arm64 image") in issues


def test_assess_runtime_stage_rewards_minimal_images():
    stage = _stage("FROM python:3.12-slim\nCOPY . /app\n")
    issues = _issues(stage, image(), image("dhi.io/python:3.12", shell=False, pm="", user="65532"), "hardened")
    assert not any(level == "breaking" for level, _ in issues)
    assert ("good", "runs as non-root user 65532") in issues
    assert ("good", "no shell or package manager for an attacker to use") in issues


def test_assess_stale_image():
    stage = _stage("FROM python:3.12-slim\n")
    issues = _issues(stage, image(), image("python:3.12-slim", created="2020-01-01T00:00:00Z"))
    assert any(level == "caution" and text.startswith("last built") for level, text in issues)


# ── Recommendations ──────────────────────────────────────────────────

def _advise(stage_text, current, cands):
    stage = _stage(stage_text)
    sa = StageAdvice(stage, Candidate(current.ref, "current", current), PYTHON)
    for img, src in cands:
        c = Candidate(img.ref, src, img)
        c.issues = assess(stage, PYTHON, current, c)
        sa.candidates.append(c)
    _recommend(sa)
    return sa


def test_recommends_best_drop_in_and_offers_alternative():
    current = image(vulns=vulns(critical=2, high=10))
    slim = image("python:3.12-slim", size=40_000_000, vulns=vulns(high=5))
    alpine = image("python:3.12-alpine", size=18_000_000, distro="alpine", pm="apk", libc="musl")
    sa = _advise("FROM python:3.12-slim\n", current, [(alpine, "official"), (slim, "official")])
    assert sa.recommended.ref == "python:3.12-slim"
    assert sa.alternative.ref == "python:3.12-alpine"
    assert [c.ref for c in sa.ranked] == ["python:3.12", "python:3.12-slim", "python:3.12-alpine"]

    # The pick stays at the top even when a later note demotes its verdict.
    sa.recommended.issues.append(Issue("caution", "pair it with a build stage"))
    assert sa.ranked[1] is sa.recommended


def test_never_recommends_a_breaking_candidate():
    current = image(vulns=vulns(high=10))
    noshell = image("dhi.io/python:3.12", shell=False, pm="", user="65532")
    sa = _advise("FROM python:3.12\nRUN pip install x\n", current, [(noshell, "hardened")])
    assert sa.recommended is None
    assert sa.alternative.ref == "dhi.io/python:3.12"


def test_no_recommendation_when_nothing_is_better():
    current = image(vulns=vulns(high=1), size=20_000_000)
    worse = image("python:3.12", size=400_000_000, vulns=vulns(critical=3))
    assert _advise("FROM python:3.12-slim\n", current, [(worse, "official")]).recommended is None


def test_same_risk_but_much_smaller_is_better():
    current = image(size=400_000_000)
    slim = image("python:3.12-slim", size=40_000_000)
    assert _advise("FROM python:3.12\n", current, [(slim, "official")]).recommended.ref == "python:3.12-slim"


# ── The whole flow, with stand-ins for the registry and OSV ──────────

class FakeRegistry:
    def __init__(self, images):
        self.images = images
        self.probed = []

    def inspect(self, ref, platform):
        img = self.images.get(str(ref))
        if img is None:
            raise BaselyError(f"{ref}: not found on {ref.host}")
        return img

    def exists(self, ref):
        self.probed.append(str(ref))
        return str(ref) in self.images


class FakeOSV:
    def scan(self, images):
        for img in images:
            img.scanned = True


def test_advisor_end_to_end():
    images = {
        "python:3.12": image("python:3.12", size=400_000_000, vulns=vulns(critical=5, high=50, fixable=20)),
        "python:3.12-slim": image("python:3.12-slim", size=43_000_000, vulns=vulns(high=5)),
        "python:3.12-alpine": image("python:3.12-alpine", size=18_000_000, distro="alpine", pm="apk", libc="musl"),
        "dhi.io/python:3.12-dev": image("dhi.io/python:3.12-dev", vulns=vulns(high=8)),
        "python:3.13-slim": image("python:3.13-slim", env={"PYTHON_VERSION": "3.13.1"}),
    }
    stages = dockerfile.parse("FROM python:3.12\nRUN apt-get update\n")
    advice = Advisor(FakeRegistry(images), FakeOSV()).advise(stages)
    (sa,) = advice.stages
    refs = {c.ref: c for c in sa.candidates}
    assert refs["dhi.io/python:3.12-alpine-dev"].verdict == "unavailable"
    assert refs["python:3.13-slim"].source == "upgrade"
    assert sa.recommended.ref == "python:3.12-slim"
    assert advice.triggered({"fixable", "better", "critical", "root"}) == {
        "fixable": 20, "better": 1, "critical": 5, "root": 1}


def test_advisor_reports_unreadable_current_image():
    advice = Advisor(FakeRegistry({}), FakeOSV()).advise(dockerfile.parse("FROM python:3.12\n"))
    assert advice.stages[0].current.image is None
    assert "not found" in advice.stages[0].current.error


@pytest.mark.parametrize("user, root", [("", True), ("0", True), ("root:root", True), ("65532", False)])
def test_runs_as_root(user, root):
    assert image(user=user).runs_as_root is root

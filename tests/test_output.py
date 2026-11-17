"""Text, Markdown, JSON and HTML output, including hostile values."""

import json

import pytest

from basely import cli, dockerfile
from basely.advise import Advisor
from basely.html import to_html
from basely.render import to_json, to_markdown, to_text
from helpers import image, vulns
from test_advise import FakeOSV, FakeRegistry

DOCKERFILE = "ARG PY=3.12\nFROM python:${PY} AS build\nRUN apt-get update\nFROM python:${PY}-slim\nCOPY --from=build /x /x\n"


def _images():
    return {
        "python:3.12": image("python:3.12", size=400_000_000, vulns=vulns(critical=2, high=20, fixable=3)),
        "python:3.12-slim": image("python:3.12-slim", size=43_000_000, vulns=vulns(high=5)),
        "dhi.io/python:3.12": image("dhi.io/python:3.12", size=23_000_000, shell=False, pm="", user="65532"),
        "dhi.io/python:3.12-dev": image("dhi.io/python:3.12-dev", size=41_000_000, vulns=vulns(high=8)),
    }


@pytest.fixture
def advice():
    a = Advisor(FakeRegistry(_images()), FakeOSV()).advise(dockerfile.parse(DOCKERFILE))
    a.source = "Dockerfile"
    return a


def test_text(advice):
    out = to_text(advice)
    assert "// build stage · build" in out and "// final stage" in out
    assert "→ python:3.12-slim" in out
    assert "- FROM python:${PY} AS build" in out and "+ FROM python:3.12-slim AS build" in out
    assert "+ FROM dhi.io/python:3.12" in out
    assert "pair it with dhi.io/python:3.12-dev in the build stage" in out
    assert "\033[" not in out


def test_markdown(advice):
    out = to_markdown(advice)
    assert "```diff" in out and "+ FROM dhi.io/python:3.12" in out
    assert "| **`dhi.io/python:3.12`** (recommended) |" in out
    assert "unavailable" in out  # the candidates the fake registry doesn't have


def test_json(advice):
    doc = json.loads(to_json(advice, {"better"}))
    final = doc["stages"][1]
    assert final["recommended"] == "dhi.io/python:3.12" and final["role"] == "runtime"
    assert final["current"]["verdict"] == "current"
    assert final["current"]["vulnerabilities"]["high"] == 5
    assert doc["failOn"]["triggered"] == {"better": 2}


def test_html(advice):
    out = to_html(advice)
    assert "<title>Base Image Advice — Dockerfile | Basely</title>" in out
    assert "2 better images" in out and "{{" not in out
    assert 'class="from-diff"' in out


def test_hostile_values_are_escaped():
    images = _images()
    images["python:3.12"].warnings.append("<script>alert(1)</script> | `x` {{TITLE}}")
    a = Advisor(FakeRegistry(images), FakeOSV()).advise(dockerfile.parse("FROM python:3.12\n"))
    a.source = "<img src=x>"
    html = to_html(a, title="{{STAGES}}")
    assert "<script>alert" not in html and "<img src=x>" not in html
    assert "{{STAGES}}" in html  # filled once, never re-expanded
    md = to_markdown(a)
    assert "<script>" not in md and "\\|" in md


def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    monkeypatch.setattr(cli, "Registry", lambda cache, **kw: FakeRegistry(_images()))
    monkeypatch.setattr(cli, "Client", lambda cache, **kw: FakeOSV())
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exit_:
        cli.main(["advise", "--no-cache", "--html", "r.html", "--json", "r.json", "--fail-on", "better"])
    assert exit_.value.code == 1
    assert (tmp_path / "r.html").exists() and json.loads((tmp_path / "r.json").read_text())["stages"]
    out, err = capsys.readouterr()
    assert "→ python:3.12-slim" in out and "failing because of better (2)" in err


def test_cli_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exit_:
        cli.main(["advise", "--no-cache"])
    assert exit_.value.code == 2
    assert "no such file (or use --image" in capsys.readouterr().err

    with pytest.raises(SystemExit) as exit_:
        cli.main(["advise", "--fail-on", "nope"])
    assert exit_.value.code == 2


def test_cli_compare(monkeypatch, capsys):
    monkeypatch.setattr(cli, "Registry", lambda cache, **kw: FakeRegistry(_images()))
    monkeypatch.setattr(cli, "Client", lambda cache, **kw: FakeOSV())
    with pytest.raises(SystemExit) as exit_:
        cli.main(["compare", "python:3.12", "python:3.12-slim", "--no-cache", "-f", "json"])
    assert exit_.value.code == 0
    doc = json.loads(capsys.readouterr().out)
    assert [c["ref"] for c in doc["stages"][0]["candidates"]] == ["python:3.12-slim"]
    assert doc["stages"][0]["candidates"][0]["source"] == "given"

"""Text, JSON and Markdown renderings of an Advice."""

from __future__ import annotations

import json
import os
import sys

from . import __version__
from .advise import Advice, Candidate, StageAdvice
from .model import SEVERITIES, Image

SOURCE_LABELS = {
    "current": "current",
    "official": "official",
    "hardened": "docker hardened",
    "chainguard": "chainguard",
    "upgrade": "newer runtime",
    "given": "given",
}


def size_label(n: int) -> str:
    if n >= 1_000_000_000:
        return f"{n / 1e9:.1f} GB"
    if n >= 10_000_000:
        return f"{n / 1e6:.0f} MB"
    return f"{n / 1e6:.1f} MB"


def serious(img: Image) -> int:
    return img.count("critical") + img.count("high")


def runtime_label(sa: StageAdvice, img: Image) -> str:
    if sa.family and not sa.family.os and img.runtime:
        return f"{sa.family.label} {img.runtime}"
    return img.distro.label if img.distro.id else (img.runtime or "unknown")


def from_line(sa: StageAdvice, ref: str) -> str:
    parts = ["FROM"]
    if sa.stage.platform:
        parts.append(f"--platform={sa.stage.platform}")
    parts.append(ref)
    if sa.stage.name:
        parts += ["AS", sa.stage.name]
    return " ".join(parts)


def original_from(sa: StageAdvice) -> str:
    return from_line(sa, sa.stage.raw)


def headline(sa: StageAdvice) -> str:
    cur = sa.current.image
    if cur is None:
        return f"Couldn't read {sa.current.ref}: {sa.current.error}"
    if not cur.scanned:
        return "Vulnerabilities couldn't be checked for this image, so there's no recommendation."
    rec = sa.recommended
    if rec is None or rec.image is None:
        if sa.alternative and sa.alternative.image:
            return f"No better drop-in, but {sa.alternative.ref} is worth the changes it needs."
        return "No candidate beats the current image."
    new = rec.image
    parts = []
    if serious(cur) != serious(new):
        parts.append(f"cuts critical and high advisories from {serious(cur)} to {serious(new)}")
    elif len(cur.vulns) != len(new.vulns):
        parts.append(f"cuts advisories from {len(cur.vulns)} to {len(new.vulns)}")
    if abs(cur.size - new.size) >= 1_000_000:
        verb = "shrinks" if new.size < cur.size else "grows"
        parts.append(f"{verb} the download from {size_label(cur.size)} to {size_label(new.size)}")
    what = " and ".join(parts) if parts else "is a better fit"
    return f"{rec.ref} {what}."


# ── JSON ──────────────────────────────────────────────────────────────

def _candidate_json(sa: StageAdvice, c: Candidate) -> dict:
    doc: dict = {"ref": c.ref, "source": c.source, "verdict": c.verdict if c.source != "current" else "current"}
    if c.error:
        doc["error"] = c.error
    img = c.image
    if img is not None:
        doc.update({
            "digest": img.digest,
            "platform": img.platform,
            "platforms": img.platforms,
            "size": img.size,
            "layers": img.layers,
            "created": img.created or None,
            "user": img.user,
            "runsAsRoot": img.runs_as_root,
            "shell": img.shell,
            "packageManager": img.package_manager or None,
            "libc": img.libc or None,
            "distro": {"id": img.distro.id, "versionId": img.distro.version_id, "ecosystem": img.distro.ecosystem},
            "runtime": runtime_label(sa, img),
            "packages": len([p for p in img.packages if not p.ecosystem]),
            "languagePackages": len(img.language_packages),
            "scanned": img.scanned,
            "risk": img.risk if img.scanned else None,
            "vulnerabilities": {
                **{s: img.count(s) for s in SEVERITIES},
                **{s: img.count(status=s) for s in ("fixable", "unfixed", "investigating")},
                "total": len(img.vulns),
                "inLanguagePackages": img.count(language=True),
                "ignored": img.ignored,
                "vexSuppressed": img.vex_suppressed,
            },
            "vexSources": img.vex_sources,
            "advisories": [
                {"id": v.id, "advisory": v.advisory, "ecosystem": v.ecosystem, "package": v.package,
                 "version": v.version, "severity": v.severity, "score": v.score, "status": v.status,
                 "fixedVersion": v.fixed_version or None}
                for v in img.vulns
            ],
        })
    doc["issues"] = [{"level": i.level, "text": i.text} for i in c.issues]
    return doc


def to_json(advice: Advice, fail_on: set[str] | None = None) -> str:
    doc: dict = {
        "tool": {"name": "basely", "version": __version__},
        "source": advice.source,
        "platform": advice.platform,
        "generated": advice.generated,
        "stages": [],
    }
    for sa in advice.stages:
        doc["stages"].append({
            "index": sa.stage.index,
            "name": sa.stage.name or None,
            "line": sa.stage.line,
            "role": sa.stage.role,
            "final": sa.stage.final,
            "from": sa.stage.raw,
            "image": sa.stage.image,
            "family": sa.family.key if sa.family else None,
            "version": sa.version or None,
            "headline": headline(sa),
            "recommended": sa.recommended.ref if sa.recommended else None,
            "alternative": sa.alternative.ref if sa.alternative else None,
            "current": _candidate_json(sa, sa.current),
            "candidates": [_candidate_json(sa, c) for c in sa.ranked[1:]],
        })
    if fail_on is not None:
        doc["failOn"] = {"categories": sorted(fail_on), "triggered": advice.triggered(fail_on)}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


# ── Terminal ──────────────────────────────────────────────────────────

# Closest terminal colours to the Full-Stack-Spectrum palette. Severity runs
# hot to cool down the spectrum; additions and good news take the brand blue.
_COLOURS = {
    "critical": "31;1", "high": "38;5;209", "medium": "33", "low": "94", "unknown": "2",
    "drop-in": "34", "minor changes": "33", "needs changes": "38;5;209", "unavailable": "2",
    "breaking": "38;5;209", "caution": "33", "note": "2", "good": "34",
    "current": "1", "dim": "2", "bold": "1", "red": "31", "blue": "94", "add": "34", "del": "31",
}


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def to_text(advice: Advice, colour: bool = False, verbose: bool = False) -> str:
    def c(style: str, text: str) -> str:
        return f"\033[{_COLOURS[style]}m{text}\033[0m" if colour and text else text

    out = [c("dim", "// ") + c("bold", "basely") + c("dim", f"  {advice.source} · {advice.platform}")]
    if not advice.stages:
        out += ["", "No stage starts from an image Basely can check (only scratch or earlier stages)."]

    for sa in advice.stages:
        stage = sa.stage
        where = f"line {stage.line}" if stage.line else ""
        role = "final stage" if stage.final else f"build stage{f' · {stage.name}' if stage.name else ''}"
        out += ["", c("dim", "// ") + c("bold", role) + c("dim", f"  {stage.raw}" + (f"  ({where})" if where else ""))]
        if sa.family is None and sa.current.image is not None and not sa.candidates:
            out.append(c("dim", "  Basely has no catalogue entry for this image, so only images you name with --with are compared."))

        rows = []
        for cand in sa.ranked:
            img = cand.image
            label = cand.ref
            if cand is sa.recommended:
                label = "→ " + label
            elif cand is sa.alternative:
                label = "◦ " + label
            else:
                label = "  " + label
            if img is None:
                rows.append((label, SOURCE_LABELS[cand.source], "", [], "", "unavailable", cand))
                continue
            counts = [str(img.count(s)) if img.scanned else "–" for s in SEVERITIES[:4]]
            fix = str(img.count(status="fixable")) if img.scanned else "–"
            verdict = "current" if cand.source == "current" else cand.verdict
            rows.append((label, SOURCE_LABELS[cand.source], size_label(img.size), counts, fix, verdict, cand))

        w_ref = max(len(r[0]) for r in rows)
        w_src = max(len(r[1]) for r in rows)
        out.append(c("dim", f"  {'image':<{w_ref}}  {'source':<{w_src}}  {'size':>7}  {'crit':>4} {'high':>4} {'med':>4} {'low':>4}  {'fix':>4}  verdict"))
        for label, src, size, counts, fix, verdict, cand in rows:
            name = c("bold", label) if cand is sa.recommended else label
            pad = " " * (w_ref - len(label))
            if cand.image is None:
                out.append(f"  {name}{pad}  {src:<{w_src}}  {c('dim', cand.error)}")
                continue
            cells = " ".join(c(SEVERITIES[i], f"{v:>4}") if v not in ("0", "–") else c("dim", f"{v:>4}")
                             for i, v in enumerate(counts))
            out.append(f"  {name}{pad}  {src:<{w_src}}  {size:>7}  {cells}  {fix:>4}  {c(verdict, verdict)}")

        out += ["", "  " + headline(sa)]
        if sa.recommended:
            out += [f"  {c('del', '- ' + original_from(sa))}", f"  {c('add', '+ ' + from_line(sa, sa.recommended.ref))}"]

        shown = [sa.current] + [x for x in (sa.recommended, sa.alternative) if x]
        if verbose:
            shown = sa.ranked
        for cand in shown:
            issues = [i for i in cand.issues if verbose or i.level != "note" or cand.source == "current"]
            if not issues:
                continue
            tag = "worth the changes" if cand is sa.alternative else ("recommended" if cand is sa.recommended else cand.source)
            out.append("")
            out.append(f"  {cand.ref} {c('dim', '(' + tag + ')')}")
            for i in issues:
                out.append(f"    {c(i.level, f'{i.level:<8}')} {i.text}")

    out.append("")
    return "\n".join(out)


# ── Markdown ──────────────────────────────────────────────────────────

def _md(text: str) -> str:
    """Escape the characters that would break a table cell or inject markup."""
    for ch in ("\\", "|", "`", "*", "_", "[", "]", "<", ">"):
        text = text.replace(ch, "\\" + ch)
    return text.replace("\n", " ")


def _code(text: str) -> str:
    # GitHub splits table cells on '|' even inside a code span, so it still
    # needs escaping there; a backtick would end the span early.
    if not text:
        return "—"
    text = " ".join(text.split()).replace("`", "").replace("|", "\\|")
    return f"`{text}`"


def _fence(text: str) -> str:
    # Backticks inside a diff fence could close it early.
    return text.replace("`", "'")


_LEVEL_MARK = {"breaking": "✗", "caution": "!", "note": "·", "good": "✓"}


def to_markdown(advice: Advice, title: str = "") -> str:
    out = [f"## {_md(title) if title else 'Base image advice'}", ""]
    out.append(f"Basely compared each base image in {_code(advice.source)} with its alternatives "
               f"for {_code(advice.platform)}, using vulnerability data from [OSV](https://osv.dev).")
    if not advice.stages:
        out += ["", "No stage starts from an image Basely can check."]

    for sa in advice.stages:
        stage = sa.stage
        role = "Final stage" if stage.final else f"Build stage {_code(stage.name) if stage.name else ''}".rstrip()
        out += ["", f"### {role}: {_code(stage.raw)}", "", f"**{_md(headline(sa))}**", ""]
        if sa.recommended:
            out += ["```diff", _fence(f"- {original_from(sa)}"), _fence(f"+ {from_line(sa, sa.recommended.ref)}"), "```", ""]

        out.append("| Image | Source | Size | Critical | High | Medium | Low | Fixable | Verdict |")
        out.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
        for cand in sa.ranked:
            img = cand.image
            name = _code(cand.ref)
            if cand is sa.recommended:
                name = f"**{name}** (recommended)"
            elif cand is sa.alternative:
                name = f"{name} (worth the changes)"
            if img is None:
                out.append(f"| {name} | {SOURCE_LABELS[cand.source]} | | | | | | | unavailable: {_md(cand.error)} |")
                continue
            nums = [str(img.count(s)) if img.scanned else "–" for s in SEVERITIES[:4]]
            fix = str(img.count(status="fixable")) if img.scanned else "–"
            verdict = "current" if cand.source == "current" else cand.verdict
            out.append(f"| {name} | {SOURCE_LABELS[cand.source]} | {size_label(img.size)} | "
                       f"{' | '.join(nums)} | {fix} | {verdict} |")

        details = [x for x in (sa.current, sa.recommended, sa.alternative) if x and x.issues]
        if details:
            out.append("")
            for cand in details:
                tag = "current" if cand is sa.current else "recommended" if cand is sa.recommended else "worth the changes"
                out.append(f"- {_code(cand.ref)} ({tag})")
                for i in cand.issues:
                    out.append(f"  - {_LEVEL_MARK[i.level]} {_md(i.text)}")

    out += ["", f"<sub>[Basely](https://github.com/fullstackspectrum/basely) {__version__}. "
                "Counts cover the image's OS and language packages, not what your build adds.</sub>", ""]
    return "\n".join(out)

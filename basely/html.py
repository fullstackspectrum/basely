"""Self-contained, offline HTML report for an Advice."""

from __future__ import annotations

import base64
import datetime
import re
from html import escape
from importlib import resources

from . import __version__
from .advise import Advice, Candidate, Issue, StageAdvice
from .model import SEVERITIES
from .render import SOURCE_LABELS, from_line, headline, original_from, runtime_label, serious, size_label

# docs/brand/basely-icon.svg, inlined so the report stays self-contained.
# Keep the two in sync.
_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<rect width="64" height="64" rx="14" fill="#0a0d12"/>'
    '<rect x="25" y="11" width="28" height="28" rx="6" fill="#0a0d12" stroke="#4f8cff" stroke-width="3.5"/>'
    '<rect x="18" y="18" width="28" height="28" rx="6" fill="#0a0d12" stroke="#f5c84c" stroke-width="3.5"/>'
    '<rect x="11" y="25" width="28" height="28" rx="6" fill="#0a0d12" stroke="#eef1f6" stroke-width="3.5"/>'
    '<path d="M19.5 39.5l5.5-5.5 5.5 5.5M19.5 46h11" fill="none" stroke="#ff4d5e" '
    'stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg>'
)

_VULNS_SHOWN = 25


def _asset(name: str) -> bytes:
    return resources.files("basely").joinpath("assets", name).read_bytes()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _fill(template: str, values: dict[str, str]) -> str:
    # One pass, so a placeholder-shaped string inside an image reference or
    # advisory can never be expanded by a later replacement.
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", lambda m: values.get(m.group(1), m.group(0)), template)


def _kind(text: str) -> str:
    return "k-" + text.replace(" ", "-")


def _stat(kind: str, label: str, value: str, sub: str, zero: bool = False) -> str:
    z = " zero" if zero else ""
    return (f'<div class="stat-card {_kind(kind)}{z}"><div class="stat-label">{escape(label)}</div>'
            f'<div class="stat-number">{escape(value)}</div><div class="stat-sub">{escape(sub)}</div></div>')


def _issues(issues: list[Issue]) -> str:
    if not issues:
        return ""
    items = "".join(f'<li><span class="badge {_kind(i.level)}">{escape(i.level)}</span>'
                    f"<span>{escape(i.text)}</span></li>" for i in issues)
    return f'<ul class="issues">{items}</ul>'


def _advice_card(sa: StageAdvice) -> str:
    rec, alt = sa.recommended, sa.alternative
    kind = "better" if rec else "none"
    label = "recommended" if rec else ("worth the changes" if alt else "no change recommended")
    body = f'<div class="advice-head">{escape(headline(sa))}</div>'
    if rec:
        body += (f'<div class="from-diff"><div class="del">{escape(original_from(sa))}</div>'
                 f'<div class="add">{escape(from_line(sa, rec.ref))}</div></div>')
        body += _issues([i for i in rec.issues if i.level != "note"])
    if alt and alt.image:
        why = f"{len(alt.image.vulns)} advisories, {serious(alt.image)} critical or high, {size_label(alt.image.size)}"
        prefix = "Worth the changes: " if rec else ""
        body += (f'<div class="alt"><div class="alt-head">{escape(prefix)}<code>{escape(alt.ref)}</code> '
                 f'<span class="stage-meta">({escape(why)})</span></div>{_issues([i for i in alt.issues if i.level != "note"])}</div>')
    return f'<div class="advice {_kind(kind)}"><div class="advice-label">{escape(label)}</div>{body}</div>'


def _vuln_list(c: Candidate) -> str:
    img = c.image
    if img is None or not img.vulns:
        return ""
    rows = []
    for v in img.vulns[:_VULNS_SHOWN]:
        fix = f"fixed in {v.fixed_version}" if v.fixed_version else v.status
        rows.append(f'<div class="{_kind(v.severity)}"><span class="sv">{escape(v.severity)}</span>'
                    f"<span>{escape(v.id)}</span><span>{escape(v.package)} {escape(v.version)} · {escape(fix)}"
                    f"{' · ' + escape(v.ecosystem) if v.ecosystem else ''}</span></div>")
    if len(img.vulns) > _VULNS_SHOWN:
        rows.append(f'<div class="more-n">… and {len(img.vulns) - _VULNS_SHOWN} more in --json</div>')
    return f'<div class="vulns">{"".join(rows)}</div>'


def _row(sa: StageAdvice, c: Candidate, largest: int) -> str:
    classes = []
    if c.source == "current":
        classes.append("is-current")
    if c is sa.recommended:
        classes.append("is-pick")
    cls = f' class="{" ".join(classes)}"' if classes else ""
    tag = SOURCE_LABELS[c.source]
    if c is sa.recommended:
        tag += " · recommended"
    elif c is sa.alternative:
        tag += " · worth the changes"
    name = f'<td class="img"><code>{escape(c.ref)}</code><small>{escape(tag)}</small>'

    img = c.image
    if img is None:
        return f'<tr{cls}>{name}</td><td colspan="8" class="err">unavailable: {escape(c.error)}</td></tr>'

    extra = _issues(c.issues) + _vuln_list(c)
    if extra:
        name += f'<details class="more"><summary>details</summary>{extra}</details>'
    name += "</td>"

    width = max(2, round(100 * img.size / largest)) if largest else 0
    size = f'<td class="num">{escape(size_label(img.size))}<span class="size-bar" style="width:{width}%"></span></td>'
    cells = []
    for s in SEVERITIES[:4]:
        n = img.count(s)
        if not img.scanned:
            cells.append('<td class="num zero">–</td>')
        elif n:
            cells.append(f'<td class="num sev {_kind(s)}">{n}</td>')
        else:
            cells.append('<td class="num zero">0</td>')
    fix = img.count(status="fixable")
    cells.append(f'<td class="num{" zero" if not fix else ""}">{fix if img.scanned else "–"}</td>')
    verdict = "current" if c.source == "current" else c.verdict
    meta = (f'<td class="meta">{escape(runtime_label(sa, img))}<br>'
            f'{escape("root" if img.runs_as_root else "user " + img.user)} · {"shell" if img.shell else "no shell"}'
            f'{" · " + escape(img.libc) if img.libc else ""}</td>')
    return (f'<tr{cls}>{name}{size}{"".join(cells)}{meta}'
            f'<td><span class="badge {_kind(verdict)}">{escape(verdict)}</span></td></tr>')


def _stage(sa: StageAdvice) -> str:
    role = "Final stage" if sa.stage.final else f"Build stage{' · ' + sa.stage.name if sa.stage.name else ''}"
    meta = f"<code>{escape(sa.stage.raw)}</code>"
    if sa.stage.line:
        meta += f" · line {sa.stage.line}"
    meta += f" · {escape(sa.stage.role)} role"
    if sa.current.image is None:
        return (f'<section><h2 class="section-title">{escape(role)}</h2><p class="stage-meta">{meta}</p>'
                f'<div class="empty">Couldn\'t read {escape(sa.current.ref)}: {escape(sa.current.error)}</div></section>')

    ranked = sa.ranked
    largest = max((c.image.size for c in ranked if c.image), default=0)
    rows = "".join(_row(sa, c, largest) for c in ranked)
    table = ('<div class="table-wrap"><table><thead><tr><th>Image</th><th class="num">Size</th>'
             '<th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th>'
             '<th class="num">Fixable</th><th>Runtime · user</th><th>Verdict</th>'
             f'</tr></thead><tbody>{rows}</tbody></table></div>')
    current_notes = _issues(sa.current.issues)
    if current_notes:
        current_notes = f'<div class="advice k-current"><div class="advice-label">current image</div>{current_notes}</div>'
    return (f'<section><h2 class="section-title">{escape(role)}</h2><p class="stage-meta">{meta}</p>'
            f"{_advice_card(sa)}{current_notes}{table}</section>")


def to_html(advice: Advice, theme: str = "dark", title: str = "") -> str:
    template = _asset("report.html").decode("utf-8")
    better = sum(1 for sa in advice.stages if sa.recommended)
    if better:
        badge_class, badge_text = "k-better", f"{better} better image{'s' if better != 1 else ''}"
    else:
        badge_class, badge_text = "k-none", "no change needed"

    candidates = sum(len(sa.candidates) for sa in advice.stages)
    final = next((sa for sa in advice.stages if sa.stage.final), advice.stages[-1] if advice.stages else None)
    stats = []
    if final and final.current.image and final.current.image.scanned:
        cur = final.current.image
        pick = final.recommended.image if final.recommended and final.recommended.image else None
        stats.append(_stat("critical", "Critical + high now", str(serious(cur)), "in the final stage's image",
                           zero=serious(cur) == 0))
        if pick:
            stats.append(_stat("better", "With the pick", str(serious(pick)), final.recommended.ref))  # type: ignore[union-attr]
        stats.append(_stat("unknown", "Download now", size_label(cur.size), "compressed layers"))
        if pick:
            stats.append(_stat("better", "With the pick", size_label(pick.size), "compressed layers"))
    stats.append(_stat("unknown", "Candidates", str(candidates),
                       f"across {len(advice.stages)} stage{'s' if len(advice.stages) != 1 else ''}"))

    hero = escape(title or advice.source)
    if final:
        sub = headline(final)
    else:
        sub = "No stage starts from an image Basely can check."

    stages = "".join(_stage(sa) for sa in advice.stages)
    if not stages:
        stages = '<div class="empty">No stage starts from an image Basely can check (only scratch or earlier stages).</div>'

    return _fill(template, {
        "THEME_ATTR": ' data-theme="light"' if theme == "light" else "",
        "FAVICON_B64": _b64(_FAVICON_SVG.encode()),
        "FONT_DISPLAY_B64": _b64(_asset("space-grotesk-var.woff2")),
        "FONT_MONO_B64": _b64(_asset("jetbrains-mono-var.woff2")),
        "TITLE": escape(title or advice.source),
        "BADGE_CLASS": badge_class,
        "BADGE_TEXT": escape(badge_text),
        "HERO_TITLE": hero,
        "HEADLINE": escape(sub),
        "STAT_CARDS": "".join(stats),
        "STAGES": stages,
        "PLATFORM": escape(advice.platform),
        "VERSION": escape(__version__),
        "REPORT_DATE": datetime.date.today().strftime("%d %b %Y"),
    })

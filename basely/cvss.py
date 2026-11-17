"""CVSS 3.x base scores from a vector string, per the FIRST specification.

Version 4.0 scoring needs a large lookup table, so 4.0-only advisories get
their severity from the upstream CVE record instead (see osv.py).
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    # The spec's Roundup, which avoids floating point surprises like 4.0000001.
    whole = round(value * 100000)
    return whole / 100000.0 if whole % 10000 == 0 else (math.floor(whole / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3."):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"

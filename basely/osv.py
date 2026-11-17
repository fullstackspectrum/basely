"""Look up an image's packages in OSV (https://osv.dev) and classify what comes back.

Distro advisories come from the distros' own trackers (Debian, Ubuntu, Alpine,
Chainguard/Wolfi), so backported fixes count as fixed. querybatch finds which
advisories apply; the full records, fetched once and cached for a day, say
whether a fix exists and how severe each one is.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import __version__, cvss
from .cache import Cache
from .errors import BaselyError
from .lang import canonical_pypi
from .model import SEVERITIES, Image, Package, Vuln

API = "https://api.osv.dev/v1"
_DAY = 24 * 60 * 60
_BATCH = 1000  # querybatch's limit
_TIMEOUT = 60
_USER_AGENT = f"basely/{__version__} (+https://github.com/fullstackspectrum/basely)"

# Distro verdicts that mean "not worth fixing here": Debian's unimportant,
# Ubuntu's negligible, Chainguard's false positives.
_IGNORED_URGENCY = {"unimportant"}
_IGNORED_PRIORITY = {"negligible"}
_WOLFI_IGNORED = {"false_positive_determination", "not_affected"}

# Kernel advisories reach images through headers like linux-libc-dev, but a
# container runs on the host's kernel, so they never apply to the image.
_KERNEL = re.compile(r"linux(-signed.*|-(aws|azure|gcp|oracle|hwe|lowlatency|meta)\S*)?|linux-lts.*")
_WOLFI_INVESTIGATING = {"detection"}


class Client:
    def __init__(self, cache: Cache | None = None, workers: int = 16) -> None:
        self.cache = cache or Cache(enabled=False)
        self.workers = workers

    def _call(self, url: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data, {"Content-Type": "application/json", "User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {}
            raise BaselyError(f"OSV returned HTTP {exc.code} for {url}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BaselyError(f"can't reach OSV ({getattr(exc, 'reason', exc)})") from None

    def affected(self, ecosystem: str, packages: list[Package]) -> list[list[str]]:
        """For each package, the IDs of the advisories that affect it."""
        out: list[list[str]] = []
        for start in range(0, len(packages), _BATCH):
            chunk = packages[start:start + _BATCH]
            queries = [{"package": {"ecosystem": ecosystem, "name": p.osv_name}, "version": p.osv_version}
                       for p in chunk]
            results = self._call(f"{API}/querybatch", {"queries": queries}).get("results", [])
            out += [[v["id"] for v in r.get("vulns", [])] for r in results]
            out += [[] for _ in range(len(chunk) - len(results))]
        return out

    def record(self, vuln_id: str) -> dict:
        cached = self.cache.get("osv", vuln_id, max_age=_DAY)
        if cached is not None:
            return cached
        data = self._call(f"{API}/vulns/{vuln_id}")
        self.cache.put("osv", vuln_id, data)
        return data

    def records(self, ids: set[str]) -> dict[str, dict]:
        ids_sorted = sorted(ids)
        with ThreadPoolExecutor(self.workers) as pool:
            return dict(zip(ids_sorted, pool.map(self.record, ids_sorted)))

    def scan(self, images: list[Image]) -> None:
        """Fill in vulns for every image, sharing advisory lookups between them."""
        hits: dict[int, list[tuple[Package, list[str]]]] = {}
        for n, image in enumerate(images):
            distro_eco = image.distro.ecosystem
            os_packages = [p for p in image.packages if not p.ecosystem]
            if os_packages and not distro_eco:
                image.warnings.append(f"OSV has no advisories for {image.distro.label}, "
                                      "so its OS packages weren't checked")
            # Several binaries share a source package; ask about each source once.
            by_eco: dict[str, dict[tuple[str, str], Package]] = {}
            for p in image.packages:
                eco = p.ecosystem or distro_eco
                if eco:
                    by_eco.setdefault(eco, {}).setdefault((p.osv_name, p.osv_version), p)
            if not by_eco:
                continue
            hits[n] = []
            for eco, unique in by_eco.items():
                pkgs = list(unique.values())
                hits[n] += list(zip(pkgs, self.affected(eco, pkgs)))

        records = self.records({i for pairs in hits.values() for _, ids in pairs for i in ids})

        # Records with no CVSS vector at all borrow the upstream CVE's score.
        upstream_needed = {_cve(r) for r in records.values() if r and _score(r)[0] is None and _cve(r)}
        upstream = self.records({c for c in upstream_needed if c and c not in records})

        for n, pairs in hits.items():
            image = images[n]
            classify(image, pairs, records, upstream)


def _cve(record: dict) -> str:
    for alias in [record.get("id", "")] + record.get("upstream", []) + record.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    rid = record.get("id", "")
    # DEBIAN-CVE-2024-1234, ALPINE-CVE-..., UBUNTU-CVE-...
    if "-CVE-" in rid:
        return rid[rid.index("CVE-"):]
    return ""


def _key(record: dict, fallback: str) -> str:
    """One name per issue. The CVE when there is one; otherwise the smallest of
    the record's own ID and its aliases, so a GHSA and the PYSEC record that
    aliases it land on the same key."""
    cve = _cve(record)
    if cve:
        return cve
    names = [record.get("id") or fallback] + list(record.get("aliases", []))
    return min(n for n in names if n)


# GitHub's advisory severities, used when a record has no CVSS vector.
_GHSA_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def _score(record: dict) -> tuple[float | None, str]:
    """A CVSS score (3.x preferred, then 4.0) and a fallback severity label:
    Ubuntu's priority or GitHub's severity."""
    by_type: dict[str, float | None] = {}
    label = ""
    for s in record.get("severity", []):
        kind = s.get("type", "")
        if kind in ("CVSS_V3", "CVSS_V4") and by_type.get(kind) is None:
            by_type[kind] = cvss.score(s.get("score", ""))
        elif kind == "Ubuntu":
            label = s.get("score", "").lower()
    ghsa = str((record.get("database_specific") or {}).get("severity", "")).lower()
    if not label and ghsa in _GHSA_SEVERITY:
        label = _GHSA_SEVERITY[ghsa]
    score = by_type.get("CVSS_V3")
    if score is None:
        score = by_type.get("CVSS_V4")
    return score, label


def _affected_entry(record: dict, ecosystem: str, name: str) -> dict:
    same = (lambda a, b: canonical_pypi(a) == canonical_pypi(b)) if ecosystem == "PyPI" else (lambda a, b: a == b)
    for a in record.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("ecosystem") == ecosystem and same(pkg.get("name", ""), name):
            return a
    return {}


def classify(image: Image, pairs: list[tuple[Package, list[str]]], records: dict[str, dict],
             upstream: dict[str, dict]) -> None:
    found: dict[str, Vuln] = {}
    ignored: set[str] = set()

    for pkg, ids in pairs:
        eco = pkg.ecosystem or image.distro.ecosystem
        if not pkg.ecosystem and _KERNEL.fullmatch(pkg.osv_name):
            ignored.update(_key(records.get(vid) or {}, vid) for vid in ids)
            continue
        for vid in ids:
            record = records.get(vid) or {}
            entry = _affected_entry(record, eco, pkg.osv_name)
            spec = entry.get("ecosystem_specific", {}) or {}
            key = _key(record, vid)

            status = "unfixed"
            fixed = [e["fixed"] for r in entry.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
            if fixed:
                status = "fixable"

            # Each distro says "won't fix" or "not really affected" in its own way.
            if spec.get("urgency") in _IGNORED_URGENCY:
                ignored.add(key)
                continue
            wolfi = {c.get("latest_event_status", "") for c in spec.get("components", [])}
            if wolfi & _WOLFI_IGNORED:
                ignored.add(key)
                continue
            if not fixed and wolfi & _WOLFI_INVESTIGATING:
                status = "investigating"

            score, label = _score(record)
            if label in _IGNORED_PRIORITY:
                ignored.add(key)
                continue
            if score is None and key in upstream:
                score, _ = _score(upstream[key] or {})
            sev = cvss.severity(score)
            if sev == "unknown" and label in SEVERITIES:
                sev = label

            vuln = Vuln(id=key, advisory=vid, package=pkg.osv_name, version=pkg.osv_version, severity=sev,
                        score=score, status=status, fixed_version=fixed[-1] if fixed else "",
                        summary=(record.get("summary") or record.get("details") or "").strip().split("\n")[0][:200],
                        ecosystem=eco)
            # One CVE can hit several source packages; keep the worst view of it.
            prior = found.get(key)
            if prior is None or _rank(vuln) < _rank(prior):
                found[key] = vuln

    image.vulns = sorted(found.values(), key=lambda v: (_rank(v), v.id))
    image.ignored = len(ignored - set(found))
    image.scanned = True


def _rank(v: Vuln) -> tuple[int, int]:
    return SEVERITIES.index(v.severity), {"fixable": 0, "unfixed": 1, "investigating": 2}[v.status]

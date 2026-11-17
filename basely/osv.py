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
            eco = image.distro.ecosystem
            if not eco or not image.packages:
                if image.packages and not eco:
                    image.warnings.append(f"OSV has no advisories for {image.distro.label}, so vulnerabilities weren't checked")
                continue
            # Several binaries share a source package; ask about each source once.
            sources = {(p.osv_name, p.osv_version): p for p in image.packages}
            unique = list(sources.values())
            hits[n] = list(zip(unique, self.affected(eco, unique)))

        records = self.records({i for pairs in hits.values() for _, ids in pairs for i in ids})

        # Records with only a CVSS 4 vector borrow the upstream CVE's 3.x score.
        upstream_needed = {_cve(r) for r in records.values() if r and _score(r)[0] is None and _cve(r)}
        upstream = self.records({c for c in upstream_needed if c})

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


def _score(record: dict) -> tuple[float | None, str]:
    """CVSS 3.x score if there is one, plus Ubuntu's own priority if given."""
    score = None
    priority = ""
    for s in record.get("severity", []):
        if s.get("type") == "CVSS_V3" and score is None:
            score = cvss.base_score(s.get("score", ""))
        elif s.get("type") == "Ubuntu":
            priority = s.get("score", "").lower()
    return score, priority


def _affected_entry(record: dict, ecosystem: str, name: str) -> dict:
    for a in record.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("ecosystem") == ecosystem and pkg.get("name") == name:
            return a
    return {}


def classify(image: Image, pairs: list[tuple[Package, list[str]]], records: dict[str, dict],
             upstream: dict[str, dict]) -> None:
    eco = image.distro.ecosystem
    found: dict[str, Vuln] = {}
    ignored: set[str] = set()

    for pkg, ids in pairs:
        if _KERNEL.fullmatch(pkg.osv_name):
            ignored.update(_cve(records.get(vid) or {}) or vid for vid in ids)
            continue
        for vid in ids:
            record = records.get(vid) or {}
            entry = _affected_entry(record, eco, pkg.osv_name)
            spec = entry.get("ecosystem_specific", {}) or {}
            key = _cve(record) or vid

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

            score, priority = _score(record)
            if priority in _IGNORED_PRIORITY:
                ignored.add(key)
                continue
            if score is None and key in upstream:
                score, _ = _score(upstream[key] or {})
            sev = cvss.severity(score)
            if sev == "unknown" and priority in SEVERITIES:
                sev = priority

            vuln = Vuln(id=key, advisory=vid, package=pkg.osv_name, version=pkg.osv_version, severity=sev,
                        score=score, status=status, fixed_version=fixed[-1] if fixed else "",
                        summary=(record.get("summary") or record.get("details") or "").strip().split("\n")[0][:200])
            # One CVE can hit several source packages; keep the worst view of it.
            prior = found.get(key)
            if prior is None or _rank(vuln) < _rank(prior):
                found[key] = vuln

    image.vulns = sorted(found.values(), key=lambda v: (_rank(v), v.id))
    image.ignored = len(ignored - set(found))
    image.scanned = True


def _rank(v: Vuln) -> tuple[int, int]:
    return SEVERITIES.index(v.severity), {"fixable": 0, "unfixed": 1, "investigating": 2}[v.status]

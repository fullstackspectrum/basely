"""Apply OpenVEX statements: a vendor's (or your own) word on which advisories
don't affect an image.

Vendors attach VEX to an image's platform manifest as an in-toto attestation,
found through the OCI referrers API. Docker Hardened Images do this; any
registry and image that follow the same convention work too. You can also pass
your own OpenVEX documents with --vex.

A statement applies to an advisory when it names the same vulnerability (CVE or
advisory ID, aliases included) and, if it lists packages, one of them is the
affected package. not_affected and fixed take the advisory out of the counts;
under_investigation marks it as such; affected changes nothing.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from dataclasses import dataclass, field

from .cache import Cache
from .errors import BaselyError
from .lang import canonical_pypi
from .model import Image
from .refs import ImageRef

_DAY = 24 * 60 * 60
_OPENVEX = "https://openvex.dev/ns"
_SUPPRESS = {"not_affected", "fixed"}


@dataclass
class Statement:
    vulns: set[str]                 # CVE and aliases, upper-cased
    status: str
    packages: set[str] = field(default_factory=set)  # empty: any package
    justification: str = ""


def _purl_name(purl: str) -> str:
    """pkg:deb/debian/openssl@3.5?arch=amd64 → openssl; pkg:npm/%40babel/core@7 → @babel/core."""
    if not purl.startswith("pkg:"):
        return ""
    body = purl[4:].split("?", 1)[0].split("#", 1)[0].split("@", 1)[0]
    kind, _, rest = body.partition("/")
    parts = [urllib.parse.unquote(p) for p in rest.split("/") if p]
    if not parts:
        return ""
    if kind == "npm" and len(parts) >= 2 and parts[-2].startswith("@"):
        return f"{parts[-2]}/{parts[-1]}"
    if kind == "maven" and len(parts) >= 2:
        return f"{parts[-2]}:{parts[-1]}"
    if kind == "golang":
        return "/".join(parts)
    if kind in ("oci", "docker"):
        return ""  # the image itself, not a package in it
    return parts[-1]


def _norm(name: str) -> str:
    return canonical_pypi(name)


def parse(doc: dict) -> list[Statement]:
    """Statements from an OpenVEX document, an in-toto statement wrapping one,
    or a DSSE envelope around either."""
    if "payload" in doc and "payloadType" in doc:
        doc = json.loads(base64.b64decode(doc["payload"]))
    if "predicate" in doc and isinstance(doc["predicate"], dict):
        doc = doc["predicate"]
    out: list[Statement] = []
    for st in doc.get("statements") or []:
        if not isinstance(st, dict):
            continue
        vuln = st.get("vulnerability")
        names: set[str] = set()
        if isinstance(vuln, dict):
            names |= {str(vuln.get("name", ""))} | {str(a) for a in vuln.get("aliases", []) or []}
        elif isinstance(vuln, str):
            names.add(vuln)  # OpenVEX 0.0.x wrote the ID directly
        names = {n.upper() for n in names if n}
        status = str(st.get("status", "")).lower()
        if not names or not status:
            continue
        packages: set[str] = set()
        for product in st.get("products") or []:
            if isinstance(product, str):
                product = {"@id": product}
            for item in [product, *(product.get("subcomponents") or [])]:
                purl = item.get("@id", "") or (item.get("identifiers") or {}).get("purl", "")
                name = _purl_name(purl)
                if name:
                    packages.add(_norm(name))
        out.append(Statement(names, status, packages, str(st.get("justification", ""))))
    return out


def load_file(path: str) -> list[Statement]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise BaselyError(f"{path}: can't read ({exc.strerror})") from None
    except ValueError:
        raise BaselyError(f"{path}: isn't JSON") from None
    statements = parse(doc) if isinstance(doc, dict) else []
    if not statements:
        raise BaselyError(f"{path}: no OpenVEX statements found")
    return statements


def fetch(registry, ref: ImageRef, digest: str, cache: Cache) -> list[Statement]:
    """OpenVEX attestations attached to a platform manifest, cached for a day
    (vendors update VEX without rebuilding the image)."""
    key = f"{ref.host}/{ref.repo}@{digest}"
    cached = cache.get("vex", key, max_age=_DAY)
    if cached is None:
        docs = []
        for m in registry.referrers(ref, digest):
            predicate = (m.get("annotations") or {}).get("in-toto.io/predicate-type", "")
            if not (predicate.startswith(_OPENVEX) or "openvex" in m.get("artifactType", "")):
                continue
            try:
                manifest, _ = registry.manifest(ref, m["digest"])
                for layer in manifest.get("layers", []):
                    docs.append(json.loads(registry.blob(ref, layer["digest"])))
            except (BaselyError, ValueError, KeyError):
                continue
        cached = docs
        cache.put("vex", key, cached)
    return [s for doc in cached if isinstance(doc, dict) for s in parse(doc)]


def apply(image: Image, statements: list[Statement], source: str) -> int:
    """Take what the statements rule out of image.vulns. Returns how many."""
    if not statements:
        return 0
    by_vuln: dict[str, list[Statement]] = {}
    for st in statements:
        for name in st.vulns:
            by_vuln.setdefault(name, []).append(st)

    kept, removed = [], 0
    for v in image.vulns:
        verdict = ""
        for name in {v.id.upper(), v.advisory.upper()}:
            for st in by_vuln.get(name, []):
                if st.packages and _norm(v.package) not in st.packages:
                    continue
                verdict = st.status  # later statements win, as OpenVEX intends
        if verdict in _SUPPRESS:
            removed += 1
            continue
        if verdict == "under_investigation" and v.status == "unfixed":
            v.status = "investigating"
        kept.append(v)

    image.vulns = kept
    if removed:
        image.vex_suppressed += removed
        if source not in image.vex_sources:
            image.vex_sources.append(source)
    return removed

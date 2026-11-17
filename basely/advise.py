"""Compare each stage's base image with its alternatives and pick a better one.

A candidate is judged on two things: risk (severity-weighted advisories from
OSV) and fit (would this stage still build and run on it). Fit problems come in
two strengths. Breaking ones, like a stage with RUN steps on an image with no
shell, rule a candidate out of the recommendation. Cautions, like musl instead
of glibc, are listed but don't.
"""

from __future__ import annotations

import datetime
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import catalogue, vex
from .cache import Cache
from .catalogue import Family
from .dockerfile import Stage
from .errors import BaselyError
from .model import Image, is_language
from .osv import Client
from .refs import parse
from .registry import Registry

STALE_DAYS = 90
FAIL_ON_CHOICES = ("fixable", "critical", "better", "root")
_MAIN_PLATFORMS = ("linux/amd64", "linux/arm64")


@dataclass
class Issue:
    level: str  # breaking, caution, note, good
    text: str


@dataclass
class Candidate:
    ref: str
    source: str  # current, official, hardened, chainguard, upgrade, given
    image: Image | None = None
    error: str = ""
    issues: list[Issue] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.image is None:
            return "unavailable"
        if any(i.level == "breaking" for i in self.issues):
            return "needs changes"
        if any(i.level == "caution" for i in self.issues):
            return "minor changes"
        return "drop-in"


@dataclass
class StageAdvice:
    stage: Stage
    current: Candidate
    family: Family | None = None
    version: str = ""
    candidates: list[Candidate] = field(default_factory=list)
    recommended: Candidate | None = None
    alternative: Candidate | None = None

    @property
    def ranked(self) -> list[Candidate]:
        """Current image, then the pick and the alternative, then the rest best
        first, then what couldn't be read."""
        order = {"drop-in": 0, "minor changes": 1, "needs changes": 2}
        picks = [c for c in (self.recommended, self.alternative) if c]
        rest = sorted((c for c in self.candidates if c.image and c not in picks),
                      key=lambda c: (order[c.verdict], *_key(c)[1:]))
        return [self.current, *picks, *rest] + [c for c in self.candidates if not c.image]


@dataclass
class Advice:
    source: str
    platform: str
    stages: list[StageAdvice]
    generated: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
                           .strftime("%Y-%m-%dT%H:%M:%SZ"))

    def triggered(self, kinds: set[str]) -> dict[str, int]:
        hits: dict[str, int] = {}
        for sa in self.stages:
            img = sa.current.image
            if img is None:
                continue
            counts = {
                "fixable": img.count(status="fixable"),
                "critical": img.count("critical"),
                "better": 1 if sa.recommended else 0,
                "root": 1 if sa.stage.final and img.runs_as_root and not _sets_user(sa.stage) else 0,
            }
            for kind in kinds:
                if counts.get(kind):
                    hits[kind] = hits.get(kind, 0) + counts[kind]
        return hits


def _sets_user(stage: Stage) -> bool:
    return bool(stage.users) and not stage.users[-1].split(":")[0] in ("root", "0")


def _key(c: Candidate) -> tuple:
    img = c.image
    assert img is not None
    breaking = any(i.level == "breaking" for i in c.issues)
    return (breaking, img.risk if img.scanned else float("inf"), img.size)


def _age_days(created: str) -> int | None:
    # Seconds are enough, and Python 3.10's fromisoformat can't read the
    # nanoseconds and Z suffix registries use.
    try:
        when = datetime.datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    return (now - when).days


def _runtime(family: Family | None, image: Image) -> str:
    if family is None:
        return ""
    return catalogue.runtime_version(family, image)


def assess(stage: Stage, family: Family | None, current: Image, cand: Candidate) -> list[Issue]:
    img = cand.image
    assert img is not None
    issues: list[Issue] = []

    if stage.needs_shell and not img.shell:
        issues.append(Issue("breaking", "no shell, so this stage's RUN steps can't run"))
    pm = stage.package_manager
    if pm and img.package_manager != pm and (pm != "dnf" or img.package_manager not in ("dnf", "microdnf", "yum")):
        has = f"has {img.package_manager}" if img.package_manager else "has no package manager"
        issues.append(Issue("breaking", f"RUN installs packages with {pm}, but this image {has}"))

    other = catalogue.family_for(parse(cand.ref))
    if family is not None and other is not None and other is not family and not (family.os and other.os):
        # A Go image offered for a Python stage: comparing runtimes means nothing.
        issues.append(Issue("caution", f"a {other.label} image, not a {family.label} one"))
    elif family is not None:
        if family.os:
            if current.distro.id and img.distro.id and current.distro.id != img.distro.id:
                issues.append(Issue("caution", f"{img.distro.label} instead of {current.distro.label}"))
        else:
            before = catalogue.cut(_runtime(family, current), family.precision)
            after = catalogue.cut(_runtime(family, img), family.precision)
            if before and after and before != after:
                issues.append(Issue("caution", f"{family.label} {after} instead of {before}"))

    if current.libc and img.libc and current.libc != img.libc:
        issues.append(Issue("caution", f"{img.libc} instead of {current.libc}: native code and wheels "
                                       f"built for {current.libc} won't load"))

    if pm and not img.runs_as_root and not stage.switches_to_root:
        issues.append(Issue("caution", f"runs as user {img.user}, so add USER root before installing packages"))
    if stage.final and img.runs_as_root and not current.runs_as_root:
        issues.append(Issue("caution", "runs as root"))

    for p in _MAIN_PLATFORMS:
        if p in current.platforms and p not in img.platforms:
            issues.append(Issue("caution", f"no {p} image"))

    age = _age_days(img.created)
    if age is not None and age > STALE_DAYS:
        issues.append(Issue("caution", f"last built {age} days ago"))

    if stage.final and not img.runs_as_root:
        issues.append(Issue("good", f"runs as non-root user {img.user}"))
    if stage.role == "runtime" and not img.shell:
        issues.append(Issue("good", "no shell or package manager for an attacker to use"))

    if img.needs_login:
        host = parse(cand.ref).host
        issues.append(Issue("note", f"needs a login: docker login {host}"))
    issues += _vex_issues(cand)
    if cand.source == "chainguard":
        issues.append(Issue("note", "free tier tracks latest only; pinning a version needs a Chainguard subscription"))
    for w in img.warnings:
        issues.append(Issue("note", w))
    return issues


def _vex_issues(cand: Candidate) -> list[Issue]:
    img = cand.image
    assert img is not None
    if img.vex_suppressed:
        sources = " and ".join(img.vex_sources)
        n = img.vex_suppressed
        return [Issue("good", f"{sources} rules out {n} advisor{'y' if n == 1 else 'ies'}, left out of the counts")]
    if cand.source == "hardened" and img.scanned:
        return [Issue("note", "no VEX attestation found, so the counts may be higher than Docker's own")]
    return []


def _language_note(img: Image) -> list[Issue]:
    n = img.count(language=True)
    if not n:
        return []
    names = sorted({v.package for v in img.vulns if is_language(v.ecosystem)})
    shown = ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")
    return [Issue("note", f"{n} of these advisories are in language packages the image ships ({shown})")]


def current_issues(stage: Stage, family: Family | None, cand: Candidate) -> list[Issue]:
    img = cand.image
    if img is None:
        return []
    issues: list[Issue] = []
    fixable = img.count(status="fixable")
    if fixable:
        issues.append(Issue("caution", f"{fixable} advisor{'y has' if fixable == 1 else 'ies have'} a fix "
                                       "the image hasn't picked up: rebuild or pull a newer digest"))
    issues += _language_note(img)
    issues += _vex_issues(cand)
    age = _age_days(img.created)
    if age is not None and age > STALE_DAYS:
        issues.append(Issue("caution", f"last built {age} days ago"))
    if parse(cand.ref).basename == "openjdk" and parse(cand.ref).host == "docker.io":
        issues.append(Issue("caution", "the openjdk images are deprecated and no longer updated"))
    if stage.final and img.runs_as_root and not _sets_user(stage):
        issues.append(Issue("caution", "the final image runs as root"))
    if not stage.final:
        issues.append(Issue("note", "a build stage isn't shipped, so its advisories matter less than the final stage's"))
    for w in img.warnings:
        issues.append(Issue("note", w))
    return issues


class Advisor:
    def __init__(self, registry: Registry, osv: Client, platform: str = "linux/amd64",
                 include: tuple[str, ...] = ("official", "hardened", "chainguard", "upgrade"),
                 progress=None, vendor_vex: bool = True,
                 user_vex: list[vex.Statement] | None = None) -> None:
        self.registry = registry
        self.osv = osv
        self.platform = platform
        self.include = include
        self.progress = progress or (lambda msg: None)
        self.vendor_vex = vendor_vex
        self.user_vex = user_vex or []
        self._images: dict[str, Image | BaselyError] = {}
        self._vex: dict[str, list[vex.Statement]] = {}

    def _inspect(self, ref: str, platform: str) -> Image:
        key = f"{ref}|{platform}"
        if key not in self._images:
            try:
                self._images[key] = self.registry.inspect(parse(ref), platform)
            except BaselyError as exc:
                self._images[key] = exc
        found = self._images[key]
        if isinstance(found, BaselyError):
            raise found
        # Each stage gets its own copy, since issues and warnings are per stage.
        return Image(**{**found.__dict__, "warnings": list(found.warnings)})

    def _candidate(self, ref: str, source: str, platform: str) -> Candidate:
        try:
            return Candidate(ref, source, self._inspect(ref, platform))
        except BaselyError as exc:
            return Candidate(ref, source, error=str(exc).removeprefix(f"{ref}: "))

    def _vendor_statements(self, ref: str, digest: str) -> list[vex.Statement]:
        key = f"{ref}@{digest}"
        if key not in self._vex:
            try:
                cache = getattr(self.registry, "cache", None) or Cache(enabled=False)
                self._vex[key] = vex.fetch(self.registry, parse(ref), digest, cache)
            except BaselyError:
                self._vex[key] = []
        return self._vex[key]

    def _apply_vex(self, candidates: list[Candidate]) -> None:
        scanned = [c for c in candidates if c.image and c.image.scanned]
        if self.vendor_vex:
            wanted = {(c.ref, c.image.manifest_digest) for c in scanned if c.image.manifest_digest}  # type: ignore[union-attr]
            if wanted:
                self.progress(f"checking {len(wanted)} images for VEX attestations")
                with ThreadPoolExecutor(6) as pool:
                    list(pool.map(lambda w: self._vendor_statements(*w), wanted))
        for c in scanned:
            img = c.image
            assert img is not None
            if self.vendor_vex and img.manifest_digest:
                vex.apply(img, self._vendor_statements(c.ref, img.manifest_digest), "the image's own VEX")
            vex.apply(img, self.user_vex, "your VEX")

    def _upgrade(self, family: Family, version: str, role: str, current_ref: str) -> str:
        """The newest higher runtime version, as the first official suggestion for it."""
        templates = family.official.get(role, ())
        if not templates:
            return ""
        found = ""
        for v in catalogue.next_version_candidates(family, version):
            ref = templates[0].replace("{v}", v)
            try:
                if not self.registry.exists(parse(ref)):
                    break
            except BaselyError:
                break
            found = ref
        return found if found and found != current_ref else ""

    def advise(self, stages: list[Stage], extra: list[str] | None = None) -> Advice:
        """Advise on each stage. extra are images to compare against every stage."""
        plans: list[tuple[StageAdvice, list[tuple[str, str]], str]] = []
        for stage in stages:
            if not stage.is_image:
                continue
            platform = stage.platform if stage.platform and "$" not in stage.platform else self.platform
            self.progress(f"reading {stage.image}")
            current = self._candidate(stage.image, "current", platform)
            ref = parse(stage.image)
            family = catalogue.family_for(ref)
            sa = StageAdvice(stage, current, family)
            plan: list[tuple[str, str]] = [(e, "given") for e in extra or []]
            if family is not None and current.image is not None:
                tag_version, _ = catalogue.split_tag(ref.tag)
                runtime = catalogue.runtime_version(family, current.image)
                version = runtime if family.os or not tag_version else tag_version
                sa.version = catalogue.cut(version, family.precision) if version else ""
                for s in catalogue.suggestions(family, version, stage.role):
                    if s.source in self.include:
                        plan.append((s.ref, s.source))
                if "upgrade" in self.include and not family.os:
                    up = self._upgrade(family, version, stage.role, stage.image)
                    if up:
                        plan.append((up, "upgrade"))
            seen = {str(ref)}
            unique = []
            for r, src in plan:
                norm = str(parse(r))
                if norm not in seen:
                    seen.add(norm)
                    unique.append((r, src))
            plans.append((sa, unique, platform))

        jobs = [(r, src, platform) for _, plan, platform in plans for r, src in plan]
        self.progress(f"reading {len(jobs)} candidate images")
        with ThreadPoolExecutor(4) as pool:
            results = list(pool.map(lambda j: self._candidate(*j), jobs))
        it = iter(results)
        for sa, plan, _ in plans:
            sa.candidates = [next(it) for _ in plan]

        images = [c.image for sa, _, _ in plans for c in [sa.current, *sa.candidates] if c.image]
        unique_images = list({id(i): i for i in images}.values())
        self.progress(f"looking up {sum(len(i.packages) for i in unique_images)} packages in OSV")
        self.osv.scan(unique_images)
        self._apply_vex([c for sa, _, _ in plans for c in [sa.current, *sa.candidates] if c.image])

        for sa, _, _ in plans:
            for c in [sa.current, *sa.candidates]:
                if c.image and sa.family:
                    c.image.runtime = _runtime(sa.family, c.image)
            sa.current.issues = current_issues(sa.stage, sa.family, sa.current)
            if sa.current.image is None:
                continue
            for c in sa.candidates:
                if c.image:
                    c.issues = assess(sa.stage, sa.family, sa.current.image, c)
            _recommend(sa)
        _pair_build_stages([sa for sa, _, _ in plans])

        return Advice(source="", platform=self.platform, stages=[sa for sa, _, _ in plans])


def _pair_build_stages(stages: list[StageAdvice]) -> None:
    """Hardened and Chainguard images lay files out their own way, so a build
    stage that copies into one should use the same vendor's -dev variant."""
    final = next((sa for sa in stages if sa.stage.final), None)
    if final is None or final.family is None:
        return
    for pick in (final.recommended, final.alternative):
        if pick is None or pick.source not in ("hardened", "chainguard"):
            continue
        dev = next((s.ref for s in catalogue.suggestions(final.family, final.version, "build")
                    if s.source == pick.source and _same_variant(s.ref, pick.ref)), "")
        builders = [sa for sa in stages if not sa.stage.final and sa.family is final.family]
        if dev and builders:
            pick.issues.append(Issue("caution", f"pair it with {dev} in the build stage, so paths and runtime match"))


def _same_variant(dev: str, runtime: str) -> bool:
    return ("alpine" in dev) == ("alpine" in runtime)


def _better(img: Image, than: Image) -> bool:
    return img.risk < than.risk or (img.risk == than.risk and img.size < than.size * 0.8)


def _recommend(sa: StageAdvice) -> None:
    """Recommend the best drop-in, falling back to the best that needs only
    minor changes. Offer a candidate that needs more work as the alternative
    only when it at least halves the risk of the recommendation."""
    cur = sa.current.image
    assert cur is not None
    if not cur.scanned:
        return
    scanned = [c for c in sa.candidates if c.image and c.image.scanned]

    def best(verdicts: tuple[str, ...]) -> Candidate | None:
        pool = [c for c in scanned if c.verdict in verdicts and _better(c.image, cur)]  # type: ignore[arg-type]
        return min(pool, key=lambda c: (c.image.risk, c.image.size)) if pool else None  # type: ignore[union-attr]

    sa.recommended = best(("drop-in",)) or best(("minor changes",))
    floor = sa.recommended.image if sa.recommended else cur
    assert floor is not None
    others = [c for c in scanned if c is not sa.recommended and c.verdict != "drop-in"
              and c.image.risk <= floor.risk * 0.5 and _better(c.image, floor)]  # type: ignore[union-attr]
    if others:
        sa.alternative = min(others, key=lambda c: (c.verdict == "needs changes", c.image.risk, c.image.size))  # type: ignore[union-attr]

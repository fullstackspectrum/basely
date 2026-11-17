"""What Basely knows about an image, and about the vulnerabilities in it."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
LANGUAGE_ECOSYSTEMS = ("PyPI", "npm", "Go", "Maven", "RubyGems")


def is_language(ecosystem: str) -> bool:
    return ecosystem in LANGUAGE_ECOSYSTEMS


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    # The source package OSV indexes distro advisories by: dpkg's Source, apk's
    # origin. Falls back to the binary name and version.
    source: str = ""
    source_version: str = ""
    # Empty for the distro's own packages; PyPI, npm, Go, Maven or RubyGems
    # for language packages, which also record where they were found.
    ecosystem: str = ""
    path: str = ""

    @property
    def osv_name(self) -> str:
        return self.source or self.name

    @property
    def osv_version(self) -> str:
        return self.source_version or self.version


@dataclass(frozen=True)
class Distro:
    id: str = ""          # os-release ID: debian, ubuntu, alpine, wolfi, chainguard
    version_id: str = ""  # 13, 24.04, 3.22.1
    name: str = ""        # PRETTY_NAME, for display
    lts: bool = False

    @property
    def ecosystem(self) -> str:
        """The OSV ecosystem for this distro's packages, or "" if OSV has none."""
        if self.id == "debian" and self.version_id:
            return f"Debian:{self.version_id.split('.')[0]}"
        if self.id == "ubuntu" and self.version_id:
            return f"Ubuntu:{self.version_id}" + (":LTS" if self.lts else "")
        if self.id == "alpine" and self.version_id:
            return "Alpine:v" + ".".join(self.version_id.split(".")[:2])
        if self.id == "wolfi":
            return "Wolfi"
        if self.id == "chainguard":
            return "Chainguard"
        return ""

    @property
    def label(self) -> str:
        if self.id in ("wolfi", "chainguard"):
            return self.id.capitalize()
        if self.id:
            return f"{self.id.capitalize()} {self.version_id}".strip()
        return "unknown"


@dataclass
class Vuln:
    id: str               # the CVE when there is one, else the advisory ID
    advisory: str         # the distro's advisory ID, e.g. DEBIAN-CVE-2024-1234
    package: str
    version: str
    severity: str = "unknown"
    score: float | None = None
    # fixable: the distro ships a fixed version the image hasn't picked up.
    # unfixed: no fix yet. investigating: the vendor hasn't decided yet.
    status: str = "unfixed"
    fixed_version: str = ""
    summary: str = ""
    ecosystem: str = ""   # where the advisory came from: Debian:13, PyPI, Go


@dataclass
class Image:
    ref: str
    digest: str = ""
    platform: str = ""
    size: int = 0              # compressed bytes, what a pull downloads
    layers: int = 0
    created: str = ""
    user: str = ""
    env: dict[str, str] = field(default_factory=dict)
    platforms: list[str] = field(default_factory=list)
    distro: Distro = field(default_factory=Distro)
    packages: list[Package] = field(default_factory=list)
    shell: bool = False
    package_manager: str = ""  # apt, apk, dnf, microdnf, yum or ""
    libc: str = ""             # glibc, musl or ""
    runtime: str = ""          # "python 3.12.7", from the image's env or packages
    needs_login: bool = False
    warnings: list[str] = field(default_factory=list)
    vulns: list[Vuln] = field(default_factory=list)
    ignored: int = 0           # advisories the distro marks as not worth fixing
    vex_suppressed: int = 0    # advisories a VEX statement marks not affected or fixed
    vex_sources: list[str] = field(default_factory=list)
    scanned: bool = False      # vulnerabilities were looked up
    manifest_digest: str = ""  # the platform manifest, which attestations attach to

    @property
    def runs_as_root(self) -> bool:
        return self.user in ("", "0", "root") or self.user.startswith(("0:", "root:"))

    def count(self, severity: str | None = None, status: str | None = None, language: bool | None = None) -> int:
        return sum(1 for v in self.vulns
                   if (severity is None or v.severity == severity) and (status is None or v.status == status)
                   and (language is None or is_language(v.ecosystem) == language))

    @property
    def language_packages(self) -> list[Package]:
        return [p for p in self.packages if p.ecosystem]

    @property
    def risk(self) -> int:
        """One number to rank images by: severity-weighted advisory count."""
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "unknown": 1}
        return sum(weights[v.severity] for v in self.vulns)

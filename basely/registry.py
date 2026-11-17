"""A read-only OCI registry client on the standard library.

It speaks the token flow Docker Hub, dhi.io, cgr.dev and most other registries
use, reads credentials the same way docker does, and never pulls an image:
manifests and config come over HTTP, and layers stream through the package
scanner without touching disk.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__, packages
from .cache import Cache
from .errors import BaselyError
from .model import Image
from .refs import DOCKER_HUB, ImageRef

_INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
_MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
_ACCEPT = ", ".join(_INDEX_TYPES + _MANIFEST_TYPES)
_TIMEOUT = 60
_USER_AGENT = f"basely/{__version__} (+https://github.com/fullstackspectrum/basely)"


class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Blob downloads redirect to object storage with a presigned URL. Sending
    the registry's bearer token along makes S3-style stores (Cloudflare R2 for
    cgr.dev) reject the request, so drop it when the host changes."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            new.headers.pop("Authorization", None)
            new.unredirected_hdrs.pop("Authorization", None)
        return new


_opener = urllib.request.build_opener(_StripAuthOnRedirect)


# ── Credentials ──────────────────────────────────────────────────────

def _docker_config() -> dict:
    root = Path(os.environ.get("DOCKER_CONFIG") or Path.home() / ".docker")
    try:
        return json.loads((root / "config.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def credentials(host: str) -> tuple[str, str] | None:
    """Look up a login the way docker does: inline auths, then a per-registry
    credential helper, then the default credential store."""
    config = _docker_config()
    keys = ["https://index.docker.io/v1/", "index.docker.io", "docker.io"] if host == DOCKER_HUB else [host, f"https://{host}"]

    for key in keys:
        auth = config.get("auths", {}).get(key, {}).get("auth")
        if auth:
            user, _, secret = base64.b64decode(auth).decode("utf-8", "replace").partition(":")
            return user, secret

    helper = next((config["credHelpers"][k] for k in keys if k in config.get("credHelpers", {})), None)
    helper = helper or config.get("credsStore")
    if not helper:
        return None
    for key in keys:
        try:
            out = subprocess.run([f"docker-credential-{helper}", "get"], input=key, capture_output=True,
                                 text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if out.returncode == 0:
            try:
                found = json.loads(out.stdout)
            except ValueError:
                continue
            if found.get("Secret"):
                return found.get("Username", ""), found["Secret"]
    return None


# ── Client ───────────────────────────────────────────────────────────

class Registry:
    def __init__(self, cache: Cache | None = None, workers: int = 6, languages: bool = True) -> None:
        self.cache = cache or Cache(enabled=False)
        self.workers = workers
        self.languages = languages
        self._tokens: dict[tuple[str, str], str] = {}
        self._used_login: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def _request(self, ref: ImageRef, path: str, accept: str = "*/*", method: str = "GET"):
        url = f"https://{ref.api_host}/v2/{ref.repo}/{path}"
        key = (ref.api_host, ref.repo)
        for attempt in range(2):
            req = urllib.request.Request(url, method=method, headers={"Accept": accept, "User-Agent": _USER_AGENT})
            token = self._tokens.get(key)
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            try:
                return _opener.open(req, timeout=_TIMEOUT)
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    self._authenticate(ref, exc.headers.get("WWW-Authenticate", ""))
                    continue
                raise self._error(ref, exc) from None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                raise BaselyError(f"{ref}: can't reach {ref.api_host} ({reason})") from None
        raise BaselyError(f"{ref}: {ref.host} refused the request")

    def _error(self, ref: ImageRef, exc: urllib.error.HTTPError) -> BaselyError:
        if exc.code in (401, 403):
            if (ref.api_host, ref.repo) in self._used_login:
                return BaselyError(f"{ref}: your {ref.host} login doesn't give access to {ref.name}")
            return BaselyError(f"{ref}: {ref.host} needs a login (run: docker login {ref.host})")
        if exc.code == 404:
            return BaselyError(f"{ref}: not found on {ref.host}")
        if exc.code == 429:
            return BaselyError(f"{ref}: {ref.host} is rate limiting requests; log in or try again later")
        return BaselyError(f"{ref}: {ref.host} returned HTTP {exc.code}")

    def _authenticate(self, ref: ImageRef, challenge: str) -> None:
        scheme, _, rest = challenge.partition(" ")
        params = dict(re.findall(r'(\w+)="([^"]*)"', rest))
        key = (ref.api_host, ref.repo)
        login = credentials(ref.host)

        if scheme.lower() != "bearer":
            raise BaselyError(f"{ref}: {ref.host} uses {scheme or 'unknown'} auth; Basely supports token auth only")

        realm = params.get("realm")
        if not realm:
            raise BaselyError(f"{ref}: {ref.host} sent an auth challenge Basely can't follow")
        query = urllib.parse.urlencode({"service": params.get("service", ""), "scope": f"repository:{ref.repo}:pull"})
        url = f"{realm}?{query}"

        def fetch(with_login: bool) -> dict:
            req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
            if with_login and login:
                pair = f"{login[0]}:{login[1]}".encode()
                req.add_header("Authorization", "Basic " + base64.b64encode(pair).decode())
            with _opener.open(req, timeout=_TIMEOUT) as resp:
                return json.load(resp)

        try:
            data = fetch(True)
            used_login = bool(login)
        except urllib.error.HTTPError:
            if not login:
                raise BaselyError(f"{ref}: {ref.host} refused an anonymous token") from None
            # A stored login for another account shouldn't block public images.
            try:
                data, used_login = fetch(False), False
            except urllib.error.HTTPError:
                raise BaselyError(f"{ref}: {ref.host} rejected the stored login (run: docker login {ref.host})") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise BaselyError(f"{ref}: can't get a token from {realm} ({exc})") from None

        with self._lock:
            self._tokens[key] = data.get("token") or data.get("access_token") or ""
            if used_login:
                self._used_login.add(key)

    def used_login(self, ref: ImageRef) -> bool:
        return (ref.api_host, ref.repo) in self._used_login

    # ── Manifests ──

    def manifest(self, ref: ImageRef, reference: str | None = None) -> tuple[dict, str]:
        with self._request(ref, f"manifests/{reference or ref.reference}", _ACCEPT) as resp:
            body = json.load(resp)
            return body, resp.headers.get("Docker-Content-Digest", "")

    def exists(self, ref: ImageRef) -> bool:
        try:
            self._request(ref, f"manifests/{ref.reference}", _ACCEPT, method="HEAD").close()
            return True
        except BaselyError as exc:
            if "not found" in str(exc):
                return False
            raise

    def tags(self, ref: ImageRef, limit: int = 20000) -> list[str]:
        out: list[str] = []
        path: str | None = "tags/list?n=1000"
        while path and len(out) < limit:
            with self._request(ref, path, "application/json") as resp:
                out += json.load(resp).get("tags") or []
                link = resp.headers.get("Link", "")
            m = re.search(r"<[^>]*?/v2/[^>]*?/(tags/list\?[^>]*)>", link)
            path = m.group(1) if m else None
        return out

    def referrers(self, ref: ImageRef, digest: str) -> list[dict]:
        """Artifacts attached to a manifest through the OCI referrers API:
        signatures, SBOMs, VEX. Registries without the API return none."""
        try:
            with self._request(ref, f"referrers/{digest}", _INDEX_TYPES[0]) as resp:
                return json.load(resp).get("manifests") or []
        except (BaselyError, ValueError):
            return []

    def blob(self, ref: ImageRef, digest: str, limit: int = 16_000_000) -> bytes:
        with self._request(ref, f"blobs/{digest}") as resp:
            data = resp.read(limit + 1)
        if len(data) > limit:
            raise BaselyError(f"{ref}: blob {digest[:19]} is larger than {limit} bytes")
        return data

    # ── Inspect ──

    def inspect(self, ref: ImageRef, platform: str = "linux/amd64") -> Image:
        index, digest = self.manifest(ref)
        platforms: list[str] = []
        manifest = index
        if index.get("mediaType") in _INDEX_TYPES or "manifests" in index:
            entries = [m for m in index.get("manifests", []) if m.get("platform", {}).get("os") not in (None, "unknown")]
            platforms = sorted({_platform(m["platform"]) for m in entries})
            wanted = _match_platform(entries, platform)
            if wanted is None:
                raise BaselyError(f"{ref}: no {platform} image (has {', '.join(platforms) or 'none'})")
            manifest, _ = self.manifest(ref, wanted["digest"])
            manifest_digest = wanted["digest"]
        else:
            manifest_digest = digest

        # Bump the prefix when what's read from the layers changes.
        cache_key = f"v2:{'lang' if self.languages else 'os'}:{manifest_digest}"
        cached = self.cache.get("image", cache_key) if manifest_digest else None
        if cached:
            image = _image_from_cache(cached)
        else:
            image = self._read(ref, manifest)
            if manifest_digest:
                self.cache.put("image", cache_key, _image_to_cache(image))

        image.ref = str(ref)
        image.digest = digest or manifest_digest
        image.manifest_digest = manifest_digest
        image.platform = platform
        image.platforms = platforms or [platform]
        image.needs_login = self.used_login(ref) and ref.host != DOCKER_HUB
        return image

    def _read(self, ref: ImageRef, manifest: dict) -> Image:
        layers = manifest.get("layers", [])
        with self._request(ref, f"blobs/{manifest['config']['digest']}") as resp:
            config = json.load(resp)
        cfg = config.get("config") or {}
        env = dict(e.split("=", 1) for e in cfg.get("Env") or [] if "=" in e)

        warnings: list[str] = []

        def scan(layer: dict) -> packages.LayerScan | None:
            media = layer.get("mediaType", "")
            with self._request(ref, f"blobs/{layer['digest']}") as resp:
                if "zstd" in media:
                    try:
                        from compression import zstd  # Python 3.14+
                    except ImportError:
                        with self._lock:
                            warnings.append("some layers are zstd-compressed and need Python 3.14 to read; "
                                            "package results may be incomplete")
                        return None
                    return packages.scan_layer(zstd.ZstdFile(resp), "r|", self.languages)
                mode = "r|gz" if "gzip" in media else "r|*"
                try:
                    return packages.scan_layer(resp, mode, self.languages)
                except Exception as exc:  # tarfile raises a handful of types
                    raise BaselyError(f"{ref}: can't read layer {layer['digest'][:19]} ({exc})") from None

        with ThreadPoolExecutor(self.workers) as pool:
            scans = [s for s in pool.map(scan, layers) if s is not None]
        contents = packages.read(packages.merge(scans))
        if not contents.packages:
            warnings.append("no package database found, so there are no vulnerabilities to look up")

        return Image(
            ref=str(ref),
            size=sum(int(layer.get("size", 0)) for layer in layers),
            layers=len(layers),
            created=_created(config.get("created", "")),
            user=cfg.get("User") or "",
            env=env,
            distro=contents.distro,
            packages=contents.packages,
            shell=contents.shell,
            package_manager=contents.package_manager,
            libc=contents.libc,
            warnings=sorted(set(warnings)),
        )


def _platform(p: dict) -> str:
    out = f"{p.get('os')}/{p.get('architecture')}"
    return out + (f"/{p['variant']}" if p.get("variant") else "")


def _match_platform(entries: list[dict], wanted: str) -> dict | None:
    os_name, _, rest = wanted.partition("/")
    arch, _, variant = rest.partition("/")
    for m in entries:
        p = m.get("platform", {})
        if p.get("os") == os_name and p.get("architecture") == arch and (not variant or p.get("variant") == variant):
            return m
    return None


def _created(value: str) -> str:
    # Reproducible builds (distroless) stamp 1970-01-01, which is no date at all.
    return "" if value.startswith("1970-") else value


def _image_to_cache(image: Image) -> dict:
    return {
        "size": image.size, "layers": image.layers, "created": image.created, "user": image.user,
        "env": image.env, "shell": image.shell, "package_manager": image.package_manager,
        "libc": image.libc, "warnings": image.warnings,
        "distro": [image.distro.id, image.distro.version_id, image.distro.name, image.distro.lts],
        "packages": [[p.name, p.version, p.source, p.source_version, p.ecosystem, p.path] for p in image.packages],
    }


def _image_from_cache(data: dict) -> Image:
    from .model import Distro, Package

    return Image(
        ref="", size=data["size"], layers=data["layers"], created=data["created"], user=data["user"],
        env=data["env"], shell=data["shell"], package_manager=data["package_manager"], libc=data["libc"],
        warnings=data["warnings"], distro=Distro(*data["distro"]),
        packages=[Package(*p) for p in data["packages"]],
    )

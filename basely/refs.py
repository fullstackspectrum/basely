"""Image references: parse, normalise and print them the way docker does."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import BaselyError

DOCKER_HUB = "docker.io"
# Docker Hub's API lives on a different host from the one people type.
_API_HOSTS = {DOCKER_HUB: "registry-1.docker.io"}

_NAME = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*")
_TAG = re.compile(r"[\w][\w.-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class ImageRef:
    host: str
    repo: str
    tag: str = "latest"
    digest: str = ""

    @property
    def api_host(self) -> str:
        return _API_HOSTS.get(self.host, self.host)

    @property
    def reference(self) -> str:
        """What to ask the registry for: the digest when pinned, else the tag."""
        return self.digest or self.tag

    @property
    def name(self) -> str:
        """The repository as people write it: python, not docker.io/library/python."""
        if self.host == DOCKER_HUB:
            return self.repo.removeprefix("library/")
        return f"{self.host}/{self.repo}"

    @property
    def basename(self) -> str:
        return self.repo.rsplit("/", 1)[-1]

    def __str__(self) -> str:
        out = self.name
        if self.tag and not (self.digest and self.tag == "latest"):
            out += f":{self.tag}"
        if self.digest:
            out += f"@{self.digest}"
        return out

    def with_tag(self, tag: str) -> ImageRef:
        return ImageRef(self.host, self.repo, tag)


def parse(text: str) -> ImageRef:
    raw = text.strip()
    rest, _, digest = raw.partition("@")
    if digest and not _DIGEST.fullmatch(digest):
        raise BaselyError(f"{text!r}: digest must be sha256 followed by 64 hex characters")

    # A colon after the last slash starts the tag; one before it is a port.
    slash = rest.rfind("/")
    colon = rest.rfind(":")
    tag = ""
    if colon > slash:
        rest, tag = rest[:colon], rest[colon + 1:]
        if not _TAG.fullmatch(tag):
            raise BaselyError(f"{text!r}: {tag!r} isn't a valid tag")

    first, _, remainder = rest.partition("/")
    if remainder and ("." in first or ":" in first or first == "localhost"):
        host, repo = first, remainder
    else:
        host, repo = DOCKER_HUB, rest
    if host in ("index.docker.io", "registry-1.docker.io"):
        host = DOCKER_HUB
    if host == DOCKER_HUB and "/" not in repo:
        repo = f"library/{repo}"
    if not _NAME.fullmatch(repo):
        raise BaselyError(f"{text!r} isn't a valid image reference")
    return ImageRef(host, repo, tag or "latest", digest)

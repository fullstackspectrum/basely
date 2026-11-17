"""A small on-disk JSON cache, so a second run over the same images is quick.

Image facts are keyed by manifest digest and never go stale. Advisories do, so
they carry a timestamp and a maximum age.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path


def _root() -> Path:
    if os.environ.get("BASELY_CACHE_DIR"):
        return Path(os.environ["BASELY_CACHE_DIR"])
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "basely"


class Cache:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.root = _root()

    def _path(self, kind: str, key: str) -> Path:
        name = hashlib.sha256(key.encode()).hexdigest()[:40]
        return self.root / kind / f"{name}.json"

    def get(self, kind: str, key: str, max_age: float | None = None):
        if not self.enabled:
            return None
        path = self._path(kind, key)
        try:
            if max_age is not None and time.time() - path.stat().st_mtime > max_age:
                return None
            return json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            return None

    def put(self, kind: str, key: str, value) -> None:
        if not self.enabled:
            return
        path = self._path(kind, key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(value), "utf-8")
            tmp.replace(path)
        except OSError:
            pass  # A cache that can't be written just means a slower next run.

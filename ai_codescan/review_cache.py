"""Content-addressed cache keys for LLM review artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from ai_codescan.llm import LLMConfig
from ai_codescan.manifest import build_manifest

_REVIEW_CACHE_VERSION = 1


@dataclass(frozen=True, slots=True)
class ReviewCacheKey:
    """Identity of one evidence review by one concrete LLM configuration."""

    evidence_fingerprint: str
    review_fingerprint: str
    provider: str
    model: str

    def to_jsonable(self) -> dict[str, str]:
        return {
            "evidence_fingerprint": self.evidence_fingerprint,
            "review_fingerprint": self.review_fingerprint,
            "provider": self.provider,
            "model": self.model,
        }


def build_review_cache_key(evidence_fingerprint: str, llm: LLMConfig) -> ReviewCacheKey:
    """Bind evidence to the provider and model that reviewed it."""
    model = llm.model or ""
    payload = json.dumps(
        {
            "evidence_fingerprint": evidence_fingerprint,
            "model": model,
            "provider": llm.provider,
            "version": _REVIEW_CACHE_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ReviewCacheKey(
        evidence_fingerprint=evidence_fingerprint,
        review_fingerprint=hashlib.sha256(payload).hexdigest(),
        provider=llm.provider,
        model=model,
    )


def build_llm_context_fingerprint(llm: LLMConfig, *, source_root: Path) -> str:
    """Fingerprint the model identity and current cached source snapshot."""
    files: list[tuple[str, str, int]] = []
    if source_root.is_dir():
        files = [(entry.path, entry.sha256, entry.size) for entry in build_manifest(source_root)]
    payload = json.dumps(
        {
            "files": files,
            "model": llm.model or "",
            "provider": llm.provider,
            "source_exists": source_root.is_dir(),
            "version": _REVIEW_CACHE_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def read_review_cache_key(path: Path) -> ReviewCacheKey | None:
    """Read a marker, rejecting legacy or malformed marker formats."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    values = {
        field: str(data.get(field) or "")
        for field in ("evidence_fingerprint", "review_fingerprint", "provider", "model")
    }
    if not values["evidence_fingerprint"] or not values["review_fingerprint"]:
        return None
    return ReviewCacheKey(**values)

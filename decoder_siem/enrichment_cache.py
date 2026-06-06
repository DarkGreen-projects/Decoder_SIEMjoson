from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from decoder_siem.input_guard import validate_artifact_value, validate_enricher_name
from decoder_siem.models import (
    Artifact,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)

CACHEABLE_TYPES = {
    ArtifactType.HASH_SHA256,
    ArtifactType.HASH_SHA1,
    ArtifactType.HASH_MD5,
    ArtifactType.URL,
    ArtifactType.DOMAIN,
}

_DEFAULT_CACHE_PATH = Path.home() / ".local" / "share" / "decoder_siem" / "enrichment_cache.db"


def default_cache_path() -> Path:
    return _DEFAULT_CACHE_PATH


def is_cacheable(artifact_type: ArtifactType) -> bool:
    return artifact_type in CACHEABLE_TYPES


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_cached_at(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _format_age(cached_at: datetime) -> str:
    delta = _utc_now() - cached_at
    hours = int(delta.total_seconds() // 3600)
    if hours < 1:
        minutes = max(1, int(delta.total_seconds() // 60))
        return f"{minutes}m fa"
    return f"{hours}h fa"


class EnrichmentCacheStore:
    """SQLite cache for OSINT enrichment results with TTL."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        ttl_hours: int = 24,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled
        self._ttl = timedelta(hours=max(1, ttl_hours))
        self._path = path or default_cache_path()
        self.hits = 0
        self._conn: sqlite3.Connection | None = None
        if self._enabled:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self._path)
            self._conn.row_factory = sqlite3.Row
            self._init_schema()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _init_schema(self) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS enrichment_cache (
                enricher TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL,
                cached_at TEXT NOT NULL,
                PRIMARY KEY (enricher, artifact_type, normalized_value)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_enrichment_cache_cached_at "
            "ON enrichment_cache (cached_at)"
        )
        self._conn.execute("PRAGMA trusted_schema = OFF")
        self._conn.commit()

    def purge_expired(self) -> int:
        if not self._enabled or self._conn is None:
            return 0
        cutoff = (_utc_now() - self._ttl).isoformat()
        cur = self._conn.execute(
            "DELETE FROM enrichment_cache WHERE cached_at < ?",
            (cutoff,),
        )
        self._conn.commit()
        return cur.rowcount

    def get(self, enricher: str, artifact: Artifact) -> EnrichmentResult | None:
        if not self._enabled or self._conn is None or not is_cacheable(artifact.type):
            return None
        validate_enricher_name(enricher)
        validate_artifact_value(artifact.normalized_value)

        row = self._conn.execute(
            """
            SELECT result_json, cached_at FROM enrichment_cache
            WHERE enricher = ? AND artifact_type = ? AND normalized_value = ?
            """,
            (enricher, artifact.type.value, artifact.normalized_value),
        ).fetchone()
        if row is None:
            return None

        cached_at = _parse_cached_at(row["cached_at"])
        if _utc_now() - cached_at > self._ttl:
            self._conn.execute(
                """
                DELETE FROM enrichment_cache
                WHERE enricher = ? AND artifact_type = ? AND normalized_value = ?
                """,
                (enricher, artifact.type.value, artifact.normalized_value),
            )
            self._conn.commit()
            return None

        payload = json.loads(row["result_json"])
        result = EnrichmentResult.model_validate(payload)
        age = _format_age(cached_at)
        summary = result.summary or ""
        if "da cache" not in summary.lower():
            result.summary = f"{summary} (da cache, {age})".strip()
        result.data = dict(result.data)
        result.data["_from_cache"] = True
        result.data["_cached_at"] = row["cached_at"]
        self.hits += 1
        return result

    def put(self, enricher: str, artifact: Artifact, result: EnrichmentResult) -> None:
        if not self._enabled or self._conn is None or not is_cacheable(artifact.type):
            return
        validate_enricher_name(enricher)
        validate_artifact_value(artifact.normalized_value)
        if result.status not in (
            EnrichmentStatus.SUCCESS,
            EnrichmentStatus.NOT_FOUND,
            EnrichmentStatus.ERROR,
        ):
            return

        payload = result.model_dump()
        if payload.get("data"):
            clean_data = dict(payload["data"])
            clean_data.pop("_from_cache", None)
            clean_data.pop("_cached_at", None)
            payload["data"] = clean_data

        now = _utc_now().isoformat()
        self._conn.execute(
            """
            INSERT INTO enrichment_cache (
                enricher, artifact_type, normalized_value, status, result_json, cached_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(enricher, artifact_type, normalized_value) DO UPDATE SET
                status = excluded.status,
                result_json = excluded.result_json,
                cached_at = excluded.cached_at
            """,
            (
                enricher,
                artifact.type.value,
                artifact.normalized_value,
                result.status.value,
                json.dumps(payload),
                now,
            ),
        )
        self._conn.commit()

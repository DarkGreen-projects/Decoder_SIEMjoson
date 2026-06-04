from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class HttpClient:
    """HTTP client with throttle and optional file cache."""

    def __init__(
        self,
        *,
        requests_per_minute: int = 30,
        cache_dir: Path | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._min_interval = 60.0 / max(requests_per_minute, 1)
        self._last_request = 0.0
        self._cache_dir = cache_dir
        self._timeout = timeout
        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cache_key: str | None = None,
    ) -> tuple[int, dict[str, Any] | list[Any] | None, str | None]:
        if cache_key:
            cached = self._read_cache(cache_key)
            if cached is not None:
                return 200, cached, None
        try:
            status, body = self._request("GET", url, headers=headers)
            if status >= 400:
                return status, None, body
            data = json.loads(body) if body else {}
            if cache_key and status == 200:
                self._write_cache(cache_key, data)
            return status, data, None
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            return exc.code, None, err_body
        except Exception as exc:  # noqa: BLE001
            return 0, None, str(exc)

    def post_form_json(
        self,
        url: str,
        form: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
        cache_key: str | None = None,
    ) -> tuple[int, dict[str, Any] | list[Any] | None, str | None]:
        if cache_key:
            cached = self._read_cache(cache_key)
            if cached is not None:
                return 200, cached, None
        try:
            data = urllib.parse.urlencode(form).encode("utf-8")
            hdrs = dict(headers or {})
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            status, body = self._request("POST", url, data=data, headers=hdrs)
            if status >= 400:
                return status, None, body
            parsed = json.loads(body) if body else {}
            if cache_key and status == 200:
                self._write_cache(cache_key, parsed)
            return status, parsed, None
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            return exc.code, None, err_body
        except Exception as exc:  # noqa: BLE001
            return 0, None, str(exc)

    def _request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        self._throttle()
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _read_cache(self, key: str) -> dict[str, Any] | list[Any] | None:
        if not self._cache_dir:
            return None
        path = self._cache_dir / f"{key}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_cache(self, key: str, data: dict[str, Any] | list[Any]) -> None:
        if not self._cache_dir:
            return
        path = self._cache_dir / f"{key}.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

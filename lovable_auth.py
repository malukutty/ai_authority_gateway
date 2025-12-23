import os
import time
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import httpx


@dataclass(frozen=True)
class KeyPolicy:
    valid: bool
    allowed_envs: Tuple[str, ...] = ()
    requests_per_day: int = 0
    recipients_per_day: int = 0


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _parse_bearer(auth_header: str) -> str:
    if not auth_header:
        return ""
    parts = auth_header.split(" ", 1)
    if len(parts) != 2:
        return ""
    scheme, token = parts[0].strip().lower(), parts[1].strip()
    if scheme != "bearer":
        return ""
    return token


# Simple TTL cache: cache_key -> (expires_epoch, KeyPolicy)
_CACHE: Dict[str, Tuple[float, KeyPolicy]] = {}


def _cache_get(cache_key: str) -> Optional[KeyPolicy]:
    hit = _CACHE.get(cache_key)
    if not hit:
        return None
    expires_at, policy = hit
    if time.time() >= expires_at:
        _CACHE.pop(cache_key, None)
        return None
    return policy


def _cache_put(cache_key: str, policy: KeyPolicy, ttl_seconds: int) -> None:
    _CACHE[cache_key] = (time.time() + ttl_seconds, policy)


async def validate_api_key_with_lovable(
    *,
    authorization_header: str,
    env: str,
    ttl_seconds: int = 60,
) -> KeyPolicy:
    """
    Validates an API key by calling Lovable internal endpoint.
    Caches validation results for ttl_seconds.
    """
    lovable_base_url = os.getenv("LOVABLE_BASE_URL", "").strip().rstrip("/")
    internal_secret = os.getenv("INTERNAL_API_SECRET", "").strip()

    if not lovable_base_url:
        # Misconfig: auth cannot work reliably
        return KeyPolicy(valid=False)

    if not internal_secret:
        return KeyPolicy(valid=False)

    raw_key = _parse_bearer(authorization_header)
    if not raw_key:
        return KeyPolicy(valid=False)

    key_hash = _sha256_hex(raw_key)
    env_norm = (env or "dev").strip().lower()

    # Cache by key_hash + env (env matters for allowed_envs check)
    cache_key = f"{key_hash}:{env_norm}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    url = f"{lovable_base_url}/internal/keys/validate"
    payload = {"key_hash": key_hash, "env": env_norm}
    headers = {
        "Content-Type": "application/json",
        "X-Internal-Secret": internal_secret,
    }

    # Fail closed: any error => invalid
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
    except Exception:
        policy = KeyPolicy(valid=False)
        _cache_put(cache_key, policy, ttl_seconds=ttl_seconds)
        return policy

    if resp.status_code != 200:
        policy = KeyPolicy(valid=False)
        _cache_put(cache_key, policy, ttl_seconds=ttl_seconds)
        return policy

    try:
        data: Dict[str, Any] = resp.json()
    except Exception:
        policy = KeyPolicy(valid=False)
        _cache_put(cache_key, policy, ttl_seconds=ttl_seconds)
        return policy

    valid = bool(data.get("valid", False))
    allowed_envs = tuple([str(x).strip().lower() for x in data.get("allowed_envs", []) if str(x).strip()])
    requests_per_day = int(data.get("requests_per_day", 0) or 0)
    recipients_per_day = int(data.get("recipients_per_day", 0) or 0)

    # Enforce env is allowed (Lovable should do this too, but we double check)
    if not valid or env_norm not in allowed_envs:
        policy = KeyPolicy(valid=False)
        _cache_put(cache_key, policy, ttl_seconds=ttl_seconds)
        return policy

    policy = KeyPolicy(
        valid=True,
        allowed_envs=allowed_envs,
        requests_per_day=requests_per_day,
        recipients_per_day=recipients_per_day,
    )
    _cache_put(cache_key, policy, ttl_seconds=ttl_seconds)
    return policy

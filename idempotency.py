import json
import hashlib
from threading import Lock
from typing import Any, Dict, Optional, Tuple

_lock = Lock()

# key -> (fingerprint, result_payload)
# result_payload is whatever you'd want to return on replay
_IDEMPOTENCY_STORE: Dict[str, Tuple[str, Dict[str, Any]]] = {}


def fingerprint_action(env: str, action_type: str, action: Dict[str, Any]) -> str:
    """
    Create a stable fingerprint of what the idempotency key is protecting.
    If someone reuses the same idempotency key for a different action payload,
    we detect and deny.
    """
    canonical = json.dumps(
        {"env": env, "action_type": action_type, "action": action},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get(key: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    with _lock:
        return _IDEMPOTENCY_STORE.get(key)


def put_if_absent(key: str, fingerprint: str, result_payload: Dict[str, Any]) -> bool:
    """
    Store if absent. Returns True if stored, False if key already exists.
    """
    with _lock:
        if key in _IDEMPOTENCY_STORE:
            return False
        _IDEMPOTENCY_STORE[key] = (fingerprint, result_payload)
        return True


def overwrite(key: str, fingerprint: str, result_payload: Dict[str, Any]) -> None:
    """
    Overwrite existing entry (used after human approval executes).
    """
    with _lock:
        _IDEMPOTENCY_STORE[key] = (fingerprint, result_payload)

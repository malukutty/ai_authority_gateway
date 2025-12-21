import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from threading import Lock

AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "audit.log.jsonl")
_log_lock = Lock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def policy_hash(policy: Dict[str, Any]) -> str:
    """
    Hash the policy dict to create a stable fingerprint of "policy in effect"
    for this request. Uses a canonical JSON serialization.
    """
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_audit_event(event: Dict[str, Any]) -> None:
    """
    Append-only JSONL audit log. One JSON object per line.
    """
    path = Path(AUDIT_LOG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)

    line = json.dumps(event, ensure_ascii=False)
    with _log_lock:
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

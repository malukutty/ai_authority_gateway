from fastapi import Header, HTTPException
from typing import Optional, Dict, Any
import os

from keystore import sha256_hex, get_key_by_hash, env_allowed

def require_api_key(
    authorization: Optional[str] = Header(default=None),
    x_env: Optional[str] = Header(default="dev", alias="X-Env"),
) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: missing API key.")

    raw_key = authorization.split(" ", 1)[1].strip()
    if not raw_key:
        raise HTTPException(status_code=401, detail="Unauthorized: missing API key.")

    key_hash = sha256_hex(raw_key)
    rec = get_key_by_hash(key_hash)
    if not rec or rec.get("status") != "ACTIVE":
        raise HTTPException(status_code=401, detail="Unauthorized: invalid API key.")

    env = (x_env or "dev").strip().lower()
    if not env_allowed(rec.get("allowed_envs", ""), env):
        raise HTTPException(status_code=403, detail=f"Forbidden: key not allowed for env '{env}'.")

    return rec

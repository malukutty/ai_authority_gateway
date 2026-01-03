"""
Authority AI Gateway (Path B): Gateway-owned API keys + outbound message authority layer.

Run:
  python -m uvicorn main:app --reload

Env vars:
  ADMIN_TOKEN=supersecret123               # required for /internal/* and /admin/*
  KEYSTORE_DB_PATH=keystore.db             # optional
  RESEND_API_KEY=...                       # optional (if set, will send email)
  DEFAULT_FROM_EMAIL=ops@yourdomain.com     # optional (Resend)
  DEFAULT_FROM_NAME=Authority Gateway      # optional (Resend)
  APPROVAL_MODE=auto_execute|require_human_approval|simulate   # optional (default: require_human_approval)
  DENY_PROD=true|false                     # optional (default: false)
  KILL_SWITCH=true|false                   # optional (default: false)
"""

from __future__ import annotations

import os
import re
import json
import time
import uuid
import secrets
import hashlib
import sqlite3
from typing import Any, Dict, Optional, List

import httpx
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from datetime import datetime, timezone

# ----------------------------
# App
# ----------------------------

app = FastAPI(title="Authority AI Gateway", version="0.3-path-b")

# ----------------------------
# DB (SQLite)
# ----------------------------

DB_PATH = os.getenv("KEYSTORE_DB_PATH", "keystore.db")

# quick in-memory support audit (for debugging)
SUPPORT_AUDIT_LOG: List[Dict[str, Any]] = []


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash TEXT PRIMARY KEY,
                key_prefix TEXT NOT NULL,
                status TEXT NOT NULL,
                allowed_envs TEXT NOT NULL,
                requests_per_day INTEGER NOT NULL,
                recipients_per_day INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER,
                notes TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_created ON api_keys(created_at)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                decided_at INTEGER,
                decision TEXT,
                reason TEXT,
                payload_json TEXT NOT NULL,
                idempotency_key TEXT,
                api_key_hash TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idempotency (
                idem_key TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                response_json TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                ts INTEGER NOT NULL,
                event TEXT NOT NULL,
                actor TEXT,
                env TEXT,
                details_json TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
        conn.commit()
    finally:
        conn.close()


init_db()

# ----------------------------
# Helpers
# ----------------------------


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def now_ts() -> int:
    return int(time.time())


def bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def get_setting(name: str, default: str) -> str:
    v = os.getenv(name)
    return v.strip() if v is not None else default


def env_allowed(allowed_envs: str, env: str) -> bool:
    allowed = [e.strip().lower() for e in (allowed_envs or "").split(",") if e.strip()]
    return env.strip().lower() in allowed


def audit(event: str, actor: Optional[str], env: Optional[str], details: Dict[str, Any]) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO audit_log (id, ts, event, actor, env, details_json) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), now_ts(), event, actor, env, json.dumps(details, ensure_ascii=False)),
        )
        conn.commit()
    finally:
        conn.close()


def idem_get(idem_key: str) -> Optional[Dict[str, Any]]:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT response_json FROM idempotency WHERE idem_key = ? LIMIT 1",
            (idem_key,),
        ).fetchone()
        return json.loads(row["response_json"]) if row else None
    finally:
        conn.close()


def idem_put(idem_key: str, endpoint: str, response_obj: Dict[str, Any]) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO idempotency (idem_key, created_at, endpoint, response_json) VALUES (?, ?, ?, ?)",
            (idem_key, now_ts(), endpoint, json.dumps(response_obj, ensure_ascii=False)),
        )
        conn.commit()
    finally:
        conn.close()


def _log_support_audit(
    ticket_id: str,
    channel: str,
    decision: str,
    approval_id: Optional[str],
    commitment: Dict[str, Any],
    reasons: List[Dict[str, Any]],
) -> str:
    audit_id = f"aud_{uuid.uuid4()}"
    SUPPORT_AUDIT_LOG.append(
        {
            "audit_id": audit_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "support_decide",
            "ticket_id": ticket_id,
            "channel": channel,
            "decision": decision,
            "approval_id": approval_id,
            "commitment": commitment,
            "reasons": reasons,
        }
    )
    return audit_id


def create_support_approval(payload: Dict[str, Any]) -> str:
    approval_id = str(uuid.uuid4())
    conn = _conn()
    try:
        conn.execute(
            """
            INSERT INTO approvals
            (approval_id, status, created_at, payload_json, decision, api_key_hash)
            VALUES (?, 'PENDING', ?, ?, NULL, NULL)
            """,
            (
                approval_id,
                now_ts(),
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    audit(
        event="support_approval_created",
        actor="support_system",
        env=None,
        details={
            "approval_id": approval_id,
            "ticket_id": payload.get("ticket_id"),
            "channel": payload.get("channel"),
        },
    )
    return approval_id


# ----------------------------
# Auth
# ----------------------------


def require_admin(x_admin_token: str = Header(default="", alias="X-Admin-Token")) -> bool:
    expected = os.getenv("ADMIN_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=500, detail="Server misconfigured: ADMIN_TOKEN is not set.")
    if x_admin_token != expected:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid admin token.")
    return True


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

    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ? LIMIT 1", (key_hash,)).fetchone()
    finally:
        conn.close()

    if not row or row["status"] != "ACTIVE":
        raise HTTPException(status_code=401, detail="Unauthorized: invalid API key.")

    env = (x_env or "dev").strip().lower()
    if not env_allowed(row["allowed_envs"], env):
        raise HTTPException(status_code=403, detail=f"Forbidden: key not allowed for env '{env}'.")

    return dict(row)


# ----------------------------
# Models
# ----------------------------


class IssueKeyRequest(BaseModel):
    key_prefix: str = Field(default="aia_dev")
    allowed_envs: str = Field(default="dev")
    requests_per_day: int = Field(default=200, ge=1, le=100000)
    recipients_per_day: int = Field(default=50, ge=1, le=100000)
    notes: str = Field(default="")


class RevokeKeyRequest(BaseModel):
    key_hash: str


class MessageSendRequest(BaseModel):
    to: str = Field(..., description="Recipient email")
    subject: str = Field(..., description="Email subject")
    body: str = Field(..., description="Email body (plain text)")
    from_email: Optional[str] = None
    from_name: Optional[str] = None


class SupportDraft(BaseModel):
    text: str = Field(..., min_length=1, max_length=50_000)


class SupportDecideRequest(BaseModel):
    channel: str = Field(..., min_length=1, max_length=64)
    ticket_id: str = Field(..., min_length=1, max_length=128)
    draft: SupportDraft
    customer: Optional[Dict[str, Any]] = None
    conversation: Optional[Dict[str, Any]] = None


class SupportReason(BaseModel):
    code: str
    severity: str
    evidence: List[str] = []


class SuggestedEdit(BaseModel):
    text: str


class SupportDecideResponse(BaseModel):
    decision: str
    approval_id: Optional[str] = None
    reasons: List[SupportReason] = []
    suggested_edit: SuggestedEdit
    audit_id: str


# ----------------------------
# Policy: commitment detection + kill switches
# ----------------------------

COMMITMENT_PATTERNS = [
    r"\b(refund|refunds|credit|credited|free of charge|waive|waived)\b",
    r"\b(discount|discounted|price cut|reduce the price|we will lower)\b",
    r"\b(invoice|payment|paid|charge|charged|billing|bill)\b",
    r"\b(contract|msa|dpa|sow|purchase order|po)\b",
    r"\b(guarantee|guaranteed|we promise|we commit)\b",
    r"\bby (?:tomorrow|eod|end of day|friday|monday|next week)\b",
    r"\bwe will (?:deliver|ship|deploy|fix|resolve)\b",
    r"\b(cancel|cancellation|renewal|renew|terminate|termination)\b",
]

SAFE_FALLBACK_SUPPORT_REPLY = "Thanks for reaching out. I’m going to get this reviewed and follow up shortly."


def detect_commitment(text: str) -> Dict[str, Any]:
    hits: List[str] = []
    for p in COMMITMENT_PATTERNS:
        if re.search(p, text or "", re.IGNORECASE):
            hits.append(p)
    severity = "NONE"
    if hits:
        severity = "HARD_COMMITMENT"
    return {"severity": severity, "hits": hits}


def get_approval_mode(env: str, commitment_sev: str) -> str:
    mode = get_setting("APPROVAL_MODE", "require_human_approval").strip().lower()
    if mode not in ("auto_execute", "require_human_approval", "simulate"):
        mode = "require_human_approval"

    if bool_env("KILL_SWITCH", False):
        return "simulate"

    if bool_env("DENY_PROD", False) and env == "prod":
        return "require_human_approval"

    if commitment_sev != "NONE" and mode == "simulate":
        return "require_human_approval"

    return mode


def _normalize_hits(hits: Any) -> List[str]:
    if hits is None:
        return []
    if isinstance(hits, list):
        out: List[str] = []
        for h in hits:
            if isinstance(h, str):
                out.append(h)
            elif isinstance(h, dict):
                out.append(str(h.get("pattern") or h.get("match") or h.get("text") or h))
            else:
                out.append(str(h))
        return out
    return [str(hits)]


def _reasons_from_commitment(commitment: Dict[str, Any]) -> List[SupportReason]:
    severity = str(commitment.get("severity") or "NONE").upper()
    hits = _normalize_hits(commitment.get("hits"))

    if severity in ("NONE", "OK", "SAFE"):
        return []

    joined = " ".join(hits).lower()

    def has_any(words: List[str]) -> bool:
        return any(w in joined for w in words)

    reasons: List[SupportReason] = []

    if has_any(["refund", "credit", "waive", "free of charge", "no cost"]):
        reasons.append(SupportReason(code="FINANCIAL_COMMITMENT", severity="HARD", evidence=hits))

    if has_any(["invoice", "billing", "charge", "charged", "payment", "paid", "prorate"]):
        reasons.append(SupportReason(code="BILLING_CHANGE", severity="HARD", evidence=hits))

    if has_any(["cancel", "cancellation", "renew", "renewal", "terminate", "termination", "contract", "term"]):
        reasons.append(SupportReason(code="CONTRACTUAL_COMMITMENT", severity="HARD", evidence=hits))

    if not reasons:
        reasons.append(SupportReason(code="COMMITMENT_DETECTED", severity="HARD", evidence=hits))

    return reasons


def _decision_from_commitment(commitment: Dict[str, Any]) -> str:
    sev = str(commitment.get("severity") or "NONE").upper()
    if sev in ("NONE", "OK", "SAFE"):
        return "ALLOW"
    return "REQUIRE_APPROVAL"


# ----------------------------
# Email executor (Resend)
# ----------------------------


async def send_via_resend(req: MessageSendRequest) -> Dict[str, Any]:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        return {
            "executed": True,
            "provider": "stub",
            "message": "Stub executor: RESEND_API_KEY not set, no external side effects occurred.",
        }

    from_email = (req.from_email or os.getenv("DEFAULT_FROM_EMAIL", "")).strip()
    if not from_email:
        raise HTTPException(status_code=500, detail="Server misconfigured: DEFAULT_FROM_EMAIL not set.")
    from_name = (req.from_name or os.getenv("DEFAULT_FROM_NAME", "Authority Gateway")).strip()
    from_value = f"{from_name} <{from_email}>"

    payload = {
        "from": from_value,
        "to": [req.to],
        "subject": req.subject,
        "text": req.body,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
        )
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Resend error: {r.status_code} {r.text}")

    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text}
    return {"executed": True, "provider": "resend", "resend": data}


# ----------------------------
# Routes
# ----------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "kill_switch": bool_env("KILL_SWITCH", False),
        "deny_prod": bool_env("DENY_PROD", False),
        "approval_mode": get_setting("APPROVAL_MODE", "require_human_approval"),
    }


@app.post("/internal/keys/issue", dependencies=[Depends(require_admin)])
def issue_key(req: IssueKeyRequest):
    token = secrets.token_hex(24)
    raw_key = f"{req.key_prefix}_{token}"
    key_hash = sha256_hex(raw_key)

    conn = _conn()
    try:
        conn.execute(
            """
            INSERT INTO api_keys
            (key_hash, key_prefix, status, allowed_envs, requests_per_day, recipients_per_day, created_at, notes)
            VALUES (?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
            """,
            (key_hash, req.key_prefix, req.allowed_envs, req.requests_per_day, req.recipients_per_day, now_ts(), req.notes),
        )
        conn.commit()
    finally:
        conn.close()

    audit(
        event="key_issued",
        actor="admin",
        env=req.allowed_envs,
        details={"key_prefix": req.key_prefix, "key_hash_prefix": key_hash[:12], "allowed_envs": req.allowed_envs},
    )

    return {
        "api_key": raw_key,
        "key_hash": key_hash,
        "key_prefix": req.key_prefix,
        "status": "ACTIVE",
        "allowed_envs": req.allowed_envs,
        "requests_per_day": req.requests_per_day,
        "recipients_per_day": req.recipients_per_day,
    }


@app.post("/internal/keys/revoke", dependencies=[Depends(require_admin)])
def revoke_key_endpoint(req: RevokeKeyRequest):
    conn = _conn()
    try:
        cur = conn.execute(
            "UPDATE api_keys SET status='REVOKED', revoked_at=? WHERE key_hash=? AND status='ACTIVE'",
            (now_ts(), req.key_hash),
        )
        conn.commit()
        ok = cur.rowcount > 0
    finally:
        conn.close()

    audit(
        event="key_revoked",
        actor="admin",
        env=None,
        details={"ok": ok, "key_hash_prefix": (req.key_hash or "")[:12]},
    )
    return {"ok": ok}


@app.post("/v1/messages/send")
async def v1_messages_send(
    payload: MessageSendRequest,
    request: Request,
    key_rec: Dict[str, Any] = Depends(require_api_key),
    x_env: Optional[str] = Header(default="dev", alias="X-Env"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    env = (x_env or "dev").strip().lower()
    if env == "prod" and bool_env("DENY_PROD", False):
        raise HTTPException(status_code=403, detail="Execution denied: production calls are currently blocked.")

    if idempotency_key:
        cached = idem_get(f"v1_messages_send::{idempotency_key}")
        if cached is not None:
            return cached

    text = f"{payload.subject}\n{payload.body}"
    commitment = detect_commitment(text)
    approval_mode = get_approval_mode(env, commitment["severity"])

    audit(
        event="message_send_requested",
        actor=key_rec.get("key_hash", "")[:12],
        env=env,
        details={
            "to": payload.to,
            "subject_len": len(payload.subject),
            "body_len": len(payload.body),
            "commitment": commitment,
            "approval_mode": approval_mode,
            "idempotency_key": idempotency_key,
        },
    )

    if approval_mode == "simulate":
        resp = {
            "executed": False,
            "mode": "simulate",
            "commitment": commitment,
            "note": "Simulated: no external side effects occurred.",
        }
        if idempotency_key:
            idem_put(f"v1_messages_send::{idempotency_key}", "/v1/messages/send", resp)
        return resp

    if approval_mode == "require_human_approval" and commitment["severity"] != "NONE":
        approval_id = str(uuid.uuid4())
        conn = _conn()
        try:
            conn.execute(
                """
                INSERT INTO approvals
                (approval_id, status, created_at, payload_json, idempotency_key, api_key_hash)
                VALUES (?, 'PENDING', ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    now_ts(),
                    json.dumps({"type": "message_send", "message": payload.model_dump()}, ensure_ascii=False),
                    idempotency_key,
                    key_rec.get("key_hash"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        resp = {
            "executed": False,
            "commitment": commitment,
            "approval": {
                "approval_mode": "require_human_approval",
                "approval_id": approval_id,
                "status": "PENDING",
            },
            "note": "Pending human approval: message not sent.",
        }
        if idempotency_key:
            idem_put(f"v1_messages_send::{idempotency_key}", "/v1/messages/send", resp)
        return resp

    result = await send_via_resend(payload)
    resp = {
        "executed": bool(result.get("executed", False)),
        "commitment": commitment,
        "approval": {"approval_mode": "auto_execute", "approval_id": None, "status": None},
        "provider": result.get("provider"),
        "provider_result": result,
    }

    audit(
        event="message_send_executed",
        actor=key_rec.get("key_hash", "")[:12],
        env=env,
        details={"to": payload.to, "provider": resp["provider"], "idempotency_key": idempotency_key},
    )

    if idempotency_key:
        idem_put(f"v1_messages_send::{idempotency_key}", "/v1/messages/send", resp)
    return resp


@app.post("/v1/support/messages/decide", response_model=SupportDecideResponse)
def support_messages_decide(
    req: SupportDecideRequest,
    request: Request,
    key_rec: Dict[str, Any] = Depends(require_api_key),
    x_env: Optional[str] = Header(default="dev", alias="X-Env"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    env = (x_env or "dev").strip().lower()

    if idempotency_key:
        cached = idem_get(f"support_decide::{idempotency_key}")
        if cached is not None:
            return cached

    # Detect -> Explain -> Decide
    commitment = detect_commitment(req.draft.text)
    reasons_models = _reasons_from_commitment(commitment)
    reasons_dicts = [r.model_dump() for r in reasons_models]
    decision = _decision_from_commitment(commitment)

    # Create approval if needed (support approvals are system-originated)
    approval_id: Optional[str] = None
    if decision == "REQUIRE_APPROVAL":
        approval_payload = {
            "type": "support_message",
            "env": env,
            "ticket_id": req.ticket_id,
            "channel": req.channel,
            "draft": req.draft.text,
            "commitment": commitment,
            "reasons": reasons_dicts,
        }
        approval_id = create_support_approval(approval_payload)

    # Log to support audit (in-memory) + durable audit log
    audit_id = _log_support_audit(
        ticket_id=req.ticket_id,
        channel=req.channel,
        decision=decision,
        approval_id=approval_id,
        commitment=commitment,
        reasons=reasons_dicts,
    )

    audit(
        event="support_decide",
        actor=key_rec.get("key_hash", "")[:12],
        env=env,
        details={
            "ticket_id": req.ticket_id,
            "channel": req.channel,
            "decision": decision,
            "approval_id": approval_id,
            "commitment": commitment,
            "reasons": reasons_dicts,
            "idempotency_key": idempotency_key,
            "audit_id": audit_id,
        },
    )

    resp_model = SupportDecideResponse(
        decision=decision,
        approval_id=approval_id,
        reasons=reasons_models,
        suggested_edit=SuggestedEdit(text=SAFE_FALLBACK_SUPPORT_REPLY),
        audit_id=audit_id,
    )

    if idempotency_key:
        idem_put(f"support_decide::{idempotency_key}", "/v1/support/messages/decide", resp_model.model_dump())

    return resp_model


@app.post("/admin/approvals/{approval_id}/approve", dependencies=[Depends(require_admin)])
async def approve(approval_id: str, x_env: Optional[str] = Header(default="dev", alias="X-Env")):
    env = (x_env or "dev").strip().lower()

    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM approvals WHERE approval_id=? LIMIT 1",
            (approval_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Approval not found.")

        if row["status"] != "PENDING":
            return {"ok": True, "status": row["status"], "note": "Already decided."}

        payload = json.loads(row["payload_json"] or "{}")
        payload_type = payload.get("type")

        # Case A: message_send approval => execute send
        if payload_type == "message_send":
            msg_obj = payload.get("message") or {}
            msg = MessageSendRequest(**msg_obj)
            result = await send_via_resend(msg)

            conn.execute(
                "UPDATE approvals SET status='APPROVED', decided_at=?, decision='APPROVE' WHERE approval_id=?",
                (now_ts(), approval_id),
            )
            conn.commit()

            audit(
                event="approval_approved",
                actor="admin",
                env=env,
                details={"approval_id": approval_id, "type": "message_send", "provider": result.get("provider")},
            )

            return {
                "ok": True,
                "approval_id": approval_id,
                "status": "APPROVED",
                "type": "message_send",
                "executed": bool(result.get("executed", False)),
                "provider": result.get("provider"),
                "provider_result": result,
            }

        # Case B: support_message approval => mark approved only (decision gate)
        if payload_type == "support_message":
            conn.execute(
                "UPDATE approvals SET status='APPROVED', decided_at=?, decision='APPROVE' WHERE approval_id=?",
                (now_ts(), approval_id),
            )
            conn.commit()

            audit(
                event="approval_approved",
                actor="admin",
                env=env,
                details={"approval_id": approval_id, "type": "support_message"},
            )

            return {
                "ok": True,
                "approval_id": approval_id,
                "status": "APPROVED",
                "type": "support_message",
                "executed": True,
                "provider": "none",
                "provider_result": {"message": "Support decision approved (no external side effects)."},
            }

        # Unknown payload type
        conn.execute(
            "UPDATE approvals SET status='APPROVED', decided_at=?, decision='APPROVE' WHERE approval_id=?",
            (now_ts(), approval_id),
        )
        conn.commit()

        audit(
            event="approval_approved",
            actor="admin",
            env=env,
            details={"approval_id": approval_id, "type": "unknown"},
        )
        return {
            "ok": True,
            "approval_id": approval_id,
            "status": "APPROVED",
            "type": "unknown",
            "note": "Approved unknown approval type. No execution performed.",
        }
    finally:
        conn.close()


@app.post("/admin/approvals/{approval_id}/reject", dependencies=[Depends(require_admin)])
def reject(
    approval_id: str,
    reason: Optional[str] = None,
    x_env: Optional[str] = Header(default="dev", alias="X-Env"),
):
    env = (x_env or "dev").strip().lower()

    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM approvals WHERE approval_id=? LIMIT 1",
            (approval_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Approval not found.")

        if row["status"] != "PENDING":
            return {"ok": True, "status": row["status"], "note": "Already decided."}

        conn.execute(
            "UPDATE approvals SET status='REJECTED', decided_at=?, decision='REJECT', reason=? WHERE approval_id=?",
            (now_ts(), reason or "", approval_id),
        )
        conn.commit()

        audit(
            event="approval_rejected",
            actor="admin",
            env=env,
            details={"approval_id": approval_id, "reason": reason or ""},
        )

        return {"ok": True, "approval_id": approval_id, "status": "REJECTED", "reason": reason or ""}
    finally:
        conn.close()


@app.get("/admin/audit/recent", dependencies=[Depends(require_admin)])
def audit_recent(limit: int = 50):
    limit = max(1, min(int(limit), 200))
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT ts, event, actor, env, details_json FROM audit_log ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "ts": r["ts"],
                    "event": r["event"],
                    "actor": r["actor"],
                    "env": r["env"],
                    "details": json.loads(r["details_json"]) if r["details_json"] else None,
                }
            )
        return {"items": out}
    finally:
        conn.close()


@app.get("/admin/support/audit/recent", dependencies=[Depends(require_admin)])
def support_audit_recent(limit: int = 20):
    limit = max(1, min(limit, 200))
    return list(reversed(SUPPORT_AUDIT_LOG[-limit:]))

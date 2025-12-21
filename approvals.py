import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ApprovalRequest:
    approval_id: str
    status: str  # PENDING | APPROVED | DENIED
    created_utc: str
    decided_utc: Optional[str]
    reason: Optional[str]

    # What is being approved
    env: str
    model: str
    action_type: str
    action: Dict[str, Any]
    llm_output: str
    usage: Dict[str, Any]
    estimated_cost_usd: float
    policy_hash: str
    request_id: str
    idempotency_key: Optional[str]


# Simple in-memory store
APPROVALS: Dict[str, ApprovalRequest] = {}


def create_approval(**kwargs) -> ApprovalRequest:
    approval_id = str(uuid.uuid4())
    req = ApprovalRequest(
        approval_id=approval_id,
        status="PENDING",
        created_utc=utc_now_iso(),
        decided_utc=None,
        reason=None,
        **kwargs,
    )
    APPROVALS[approval_id] = req
    return req


def get_approval(approval_id: str) -> Optional[ApprovalRequest]:
    return APPROVALS.get(approval_id)


def decide_approval(approval_id: str, approve: bool, reason: Optional[str] = None) -> Optional[ApprovalRequest]:
    req = APPROVALS.get(approval_id)
    if not req:
        return None
    if req.status != "PENDING":
        return req

    req.status = "APPROVED" if approve else "DENIED"
    req.decided_utc = utc_now_iso()
    req.reason = reason
    return req


def approval_to_dict(req: ApprovalRequest) -> Dict[str, Any]:
    return asdict(req)

 

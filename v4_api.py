from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from audit_log import audit as audit_write  # uses your existing audit log writer
from approvals import create_support_approval  # uses your existing approvals table
from config import bool_env  # uses your existing env parsing helpers


router = APIRouter(prefix="/v4", tags=["v4"])


# ----------------------------
# v4 models (keep small, deterministic)
# ----------------------------

Lane = Literal["ai_agent", "human_agent", "human_manager"]
Role = Literal["agent", "team_lead", "finance_manager", "director", "legal"]
Mode = Literal["simulate", "enforce"]

CommitmentType = Literal[
    "billing.refund",
    "billing.credit",
    "pricing.discount",
    "subscription.change",
    "custom.irreversible_action",
]


class V4Actor(BaseModel):
    lane: Lane
    role: Role
    actor_id: Optional[str] = None


class V4Customer(BaseModel):
    customer_id: Optional[str] = None
    flagged: bool = False
    refunds_last_30d: int = 0
    annual_value_cents: Optional[int] = None


class V4Commitment(BaseModel):
    commitment_type: CommitmentType
    amount_cents: int = Field(default=0, ge=0, le=50_000_000)
    currency: str = Field(default="usd", max_length=8)

    ticket_id: Optional[str] = None
    note: Optional[str] = None

    # the thing we bind for approvals
    execution: Dict[str, Any] = Field(default_factory=dict)


class V4Thresholds(BaseModel):
    auto_execute_upto_cents: int
    require_team_lead_above_cents: int
    require_finance_manager_above_cents: int
    require_director_above_cents: int


class V4Policy(BaseModel):
    thresholds_by_lane: Dict[Lane, V4Thresholds]

    hard_stop_refund_pct_annual_requires_director_and_legal: int = 10
    hard_stop_customer_flagged_requires: Role = "finance_manager"
    hard_stop_refunds_30d_escalates_at: int = 3


class V4EvaluateRequest(BaseModel):
    env: str = Field(default="dev", max_length=8)
    mode: Mode = "simulate"
    actor: V4Actor
    customer: Optional[V4Customer] = None
    commitment: V4Commitment
    policy: Optional[V4Policy] = None


class V4Decision(BaseModel):
    status: Literal["allow", "escalate", "deny"]
    decision_explainer: str
    required_role: Optional[Role] = None
    required_additional_roles: List[Role] = []
    policy_path: List[str] = []
    audit_id: str
    approval_id: Optional[str] = None


# ----------------------------
# v4 defaults + evaluation
# ----------------------------

def _default_policy() -> V4Policy:
    return V4Policy(
        thresholds_by_lane={
            "ai_agent": V4Thresholds(
                auto_execute_upto_cents=2500,            # $25
                require_team_lead_above_cents=2500,
                require_finance_manager_above_cents=20000,  # $200
                require_director_above_cents=100000,     # $1000
            ),
            "human_agent": V4Thresholds(
                auto_execute_upto_cents=10000,           # $100
                require_team_lead_above_cents=10000,
                require_finance_manager_above_cents=50000,  # $500
                require_director_above_cents=200000,     # $2000
            ),
            "human_manager": V4Thresholds(
                auto_execute_upto_cents=50000,           # $500
                require_team_lead_above_cents=50000,
                require_finance_manager_above_cents=200000,  # $2000
                require_director_above_cents=500000,     # $5000
            ),
        }
    )


def _role_rank(role: Role) -> int:
    # legal is handled as an additional binding requirement, not rank
    order = {"agent": 1, "team_lead": 2, "finance_manager": 3, "director": 4}
    return order.get(role, 0)


def _meets_required(actor_role: Role, required: Role) -> bool:
    if required == "legal":
        return False
    return _role_rank(actor_role) >= _role_rank(required)


def _evaluate(req: V4EvaluateRequest) -> tuple[
    Literal["allow", "escalate", "deny"],
    str,
    Optional[Role],
    List[Role],
    List[str],
]:
    p = req.policy or _default_policy()
    actor = req.actor
    cust = req.customer
    c = req.commitment

    # Hard stop: flagged customer
    if cust and cust.flagged:
        return (
            "escalate",
            "Escalated: customer is flagged, requires finance_manager.",
            "finance_manager",
            [],
            ["hard_stop", "customer_flagged"],
        )

    # Hard stop: too many refunds
    if cust and cust.refunds_last_30d >= p.hard_stop_refunds_30d_escalates_at:
        return (
            "escalate",
            f"Escalated: customer has {cust.refunds_last_30d} refunds in 30 days.",
            "team_lead",
            [],
            ["hard_stop", "refunds_30d"],
        )

    # Hard stop: refund percent of annual value
    if c.commitment_type == "billing.refund" and cust and cust.annual_value_cents:
        pct = int((c.amount_cents * 100) / max(1, cust.annual_value_cents))
        if pct >= p.hard_stop_refund_pct_annual_requires_director_and_legal:
            return (
                "escalate",
                f"Escalated: refund is {pct}% of annual value; requires director + legal.",
                "director",
                ["legal"],
                ["hard_stop", "refund_pct_annual"],
            )

    lane = actor.lane
    t = p.thresholds_by_lane.get(lane)
    if not t:
        return ("deny", "Denied: actor lane not configured.", None, [], ["policy", "lane_missing", "deny"])

    amt = int(c.amount_cents)

    required: Optional[Role] = None
    if amt <= t.auto_execute_upto_cents:
        required = None
    elif amt > t.require_director_above_cents:
        required = "director"
    elif amt > t.require_finance_manager_above_cents:
        required = "finance_manager"
    else:
        required = "team_lead"

    if required is None:
        return ("allow", "Allowed: within auto-execute threshold for this lane.", None, [], ["thresholds", "auto_execute"])

    # THE IMPORTANT FIX:
    # Role dropdown must actually grant authority.
    if _meets_required(actor.role, required):
        return ("allow", f"Allowed: role '{actor.role}' satisfies required '{required}'.", None, [], ["thresholds", "role_satisfies"])

    return ("escalate", f"Escalated: requires '{required}' approval for this amount and lane.", required, [], ["thresholds", "require_approval"])


# ----------------------------
# endpoints
# ----------------------------

@router.post("/commitments/evaluate", response_model=V4Decision)
def v4_commitment_evaluate(req: V4EvaluateRequest):
    # Kill switch forces simulate
    if bool_env("KILL_SWITCH", False):
        req.mode = "simulate"

    status, explainer, required_role, required_additional, policy_path = _evaluate(req)
    audit_id = f"aud_{uuid.uuid4()}"

    # Log evidence (redaction is a frontend concern in v4)
    audit_write(
        event="v4_evaluate",
        actor=req.actor.actor_id or req.actor.role,
        env=req.env,
        details={
            "mode": req.mode,
            "status": status,
            "explainer": explainer,
            "required_role": required_role,
            "required_additional_roles": required_additional,
            "policy_path": policy_path,
            "actor": req.actor.model_dump(),
            "customer": (req.customer.model_dump() if req.customer else None),
            "commitment": req.commitment.model_dump(),
            "audit_id": audit_id,
        },
    )

    approval_id: Optional[str] = None

    # In enforce mode, escalations create approvals bound to the payload
    if req.mode == "enforce" and status == "escalate":
        approval_payload = {
            "type": "v4_commitment",
            "env": req.env,
            "actor": req.actor.model_dump(),
            "customer": (req.customer.model_dump() if req.customer else None),
            "commitment": req.commitment.model_dump(),
            "required_role": required_role,
            "required_additional_roles": required_additional,
            "policy_path": policy_path,
            "decision_explainer": explainer,
            "audit_id": audit_id,
        }
        approval_id = create_support_approval(approval_payload, api_key_hash=None)

    return V4Decision(
        status=status,
        decision_explainer=explainer,
        required_role=required_role,
        required_additional_roles=required_additional,
        policy_path=policy_path,
        audit_id=audit_id,
        approval_id=approval_id,
    )
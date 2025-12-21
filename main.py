import os
import uuid
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Depends, Request

from models import AIRequest, AIResponse, ActionResult, ApprovalInfo
from llm_client import call_openai
from control_state import STATE
from policy import load_policy, as_set
from costing import estimate_cost_usd
from audit_log import append_audit_event, policy_hash, utc_now_iso
from action_executor import execute_action_stub, ActionExecutionError
from approvals import create_approval, get_approval, decide_approval, approval_to_dict
from idempotency import fingerprint_action, get as idem_get, put_if_absent, overwrite

# Load variables from .env into process environment
load_dotenv()

app = FastAPI(title="AI Authority Gateway")

# Admin auth (MVP)
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "dev-admin-token")


def require_admin(x_admin_token: str = Header(default="")):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid admin token.")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "kill_switch": STATE.kill_switch,
        "deny_prod": STATE.deny_prod,
        "admin_token_is_default": (ADMIN_TOKEN == "dev-admin-token"),
    }


# --- Admin runtime toggles (MVP) ---
@app.post("/admin/kill_switch/on", dependencies=[Depends(require_admin)])
async def kill_switch_on():
    STATE.kill_switch = True
    return {"ok": True, "kill_switch": STATE.kill_switch}


@app.post("/admin/kill_switch/off", dependencies=[Depends(require_admin)])
async def kill_switch_off():
    STATE.kill_switch = False
    return {"ok": True, "kill_switch": STATE.kill_switch}


@app.post("/admin/deny_prod/on", dependencies=[Depends(require_admin)])
async def deny_prod_on():
    STATE.deny_prod = True
    return {"ok": True, "deny_prod": STATE.deny_prod}


@app.post("/admin/deny_prod/off", dependencies=[Depends(require_admin)])
async def deny_prod_off():
    STATE.deny_prod = False
    return {"ok": True, "deny_prod": STATE.deny_prod}


# --- Admin approvals endpoints (MVP) ---
@app.get("/admin/approvals/{approval_id}", dependencies=[Depends(require_admin)])
async def admin_get_approval(approval_id: str):
    req = get_approval(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found.")
    return approval_to_dict(req)


@app.post("/admin/approvals/{approval_id}/deny", dependencies=[Depends(require_admin)])
async def admin_deny_approval(approval_id: str):
    req = decide_approval(approval_id, approve=False, reason="Denied by admin.")
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found.")

    append_audit_event(
        {
            "timestamp_utc": utc_now_iso(),
            "request_id": req.request_id,
            "env": req.env,
            "model": req.model,
            "action_type": req.action_type,
            "policy_hash": req.policy_hash,
            "decision": "DENY",
            "deny_reason": "human_denied",
            "approval_id": approval_id,
            "idempotency_key": req.idempotency_key,
            "action": req.action,
        }
    )
    return {"ok": True, "status": req.status, "approval_id": approval_id}


@app.post("/admin/approvals/{approval_id}/approve", dependencies=[Depends(require_admin)])
async def admin_approve_and_execute(approval_id: str):
    req = decide_approval(approval_id, approve=True, reason="Approved by admin.")
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found.")

    if req.status != "APPROVED":
        return {"ok": True, "status": req.status, "approval_id": approval_id}

    # Idempotent approval execution: if already executed for this idempotency key, return stored result
    if req.idempotency_key:
        existing = idem_get(req.idempotency_key)
        if existing:
            stored_fingerprint, stored_payload = existing
            ar = (stored_payload.get("action_result") or {})
            if ar.get("executed") is True:
                append_audit_event(
                    {
                        "timestamp_utc": utc_now_iso(),
                        "request_id": req.request_id,
                        "env": req.env,
                        "model": req.model,
                        "action_type": req.action_type,
                        "policy_hash": req.policy_hash,
                        "decision": "ALLOW",
                        "note": "idempotent_approve_replay",
                        "approval_id": approval_id,
                        "idempotency_key": req.idempotency_key,
                    }
                )
                return {"ok": True, "status": req.status, "approval_id": approval_id, "action_result": ar}

    # Execute action now (still stubbed)
    try:
        exec_payload = execute_action_stub(req.action["type"], req.action.get("params", {}))
    except ActionExecutionError as ex:
        append_audit_event(
            {
                "timestamp_utc": utc_now_iso(),
                "request_id": req.request_id,
                "env": req.env,
                "model": req.model,
                "action_type": req.action_type,
                "policy_hash": req.policy_hash,
                "decision": "ERROR",
                "error": f"executor_failed_after_approval:{str(ex)}",
                "approval_id": approval_id,
                "idempotency_key": req.idempotency_key,
                "action": req.action,
            }
        )
        raise HTTPException(status_code=500, detail=f"Executor failed after approval: {str(ex)}")

    append_audit_event(
        {
            "timestamp_utc": utc_now_iso(),
            "request_id": req.request_id,
            "env": req.env,
            "model": req.model,
            "action_type": req.action_type,
            "policy_hash": req.policy_hash,
            "decision": "ALLOW",
            "note": "executed_after_human_approval",
            "approval_id": approval_id,
            "idempotency_key": req.idempotency_key,
            "action": req.action,
            "action_result": exec_payload,
        }
    )

    # Persist executed result into idempotency store (so repeated approve won't re-execute)
    if req.idempotency_key:
        fp = fingerprint_action(req.env, req.action_type, req.action)
        final_response = AIResponse(
            content=req.llm_output,
            action_result=ActionResult(**exec_payload),
            approval=ApprovalInfo(
                approval_mode="require_human_approval",
                approval_id=approval_id,
                status=req.status,
            ),
        )
        overwrite(req.idempotency_key, fp, final_response.dict())

    return {"ok": True, "status": req.status, "approval_id": approval_id, "action_result": exec_payload}


# --- Core choke point (LLM call only) ---
@app.post("/execute", response_model=AIResponse)
async def execute_ai(
    request: AIRequest,
    http_request: Request,
    x_env: str = Header(default="dev"),  # caller passes X-Env: prod|staging|dev
):
    env = x_env.strip().lower()

    request_id = str(uuid.uuid4())
    client_ip = http_request.client.host if http_request.client else None

    # Load policy once and reuse it for checks + hash
    policy = load_policy()
    p_hash = policy_hash(policy)

    audit_base = {
        "timestamp_utc": utc_now_iso(),
        "request_id": request_id,
        "client_ip": client_ip,
        "env": env,
        "model": request.model,
        "action_type": request.action_type,
        "policy_hash": p_hash,
        "endpoint": "/execute",
    }

    # 1) Runtime hard deny: kill switch
    if STATE.kill_switch:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": "kill_switch_enabled"})
        raise HTTPException(status_code=403, detail="Execution denied: kill switch is enabled.")

    # 2) Runtime deny prod (manual override)
    if STATE.deny_prod and env == "prod":
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": "runtime_deny_prod"})
        raise HTTPException(status_code=403, detail="Execution denied: production calls are currently blocked.")

    # 3) Policy enforcement (allowlists + optional prod blanket deny)
    allowed_envs = as_set(policy.get("allowed_envs"))
    allowed_models = as_set(policy.get("allowed_models"))
    allowed_action_types = as_set(policy.get("allowed_action_types"))
    deny_in_prod = bool(policy.get("deny_in_prod", False))

    if env not in allowed_envs:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": f"env_not_allowed:{env}"})
        raise HTTPException(status_code=403, detail=f"Execution denied: env '{env}' is not allowed by policy.")

    if request.model not in allowed_models:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": f"model_not_allowed:{request.model}"})
        raise HTTPException(status_code=403, detail=f"Execution denied: model '{request.model}' is not allowed by policy.")

    if request.action_type not in allowed_action_types:
        append_audit_event(
            {**audit_base, "decision": "DENY", "deny_reason": f"action_type_not_allowed:{request.action_type}"}
        )
        raise HTTPException(
            status_code=403,
            detail=f"Execution denied: action_type '{request.action_type}' is not allowed by policy.",
        )

    if deny_in_prod and env == "prod":
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": "policy_deny_in_prod"})
        raise HTTPException(status_code=403, detail="Execution denied: policy denies all production execution.")

    # 4) Cost guardrails (PRE)
    max_prompt_chars = int(policy.get("max_prompt_chars", 0) or 0)
    max_output_tokens = int(policy.get("max_output_tokens", 0) or 0)

    prompt_text = "\n".join([m.content for m in request.messages])
    if max_prompt_chars > 0 and len(prompt_text) > max_prompt_chars:
        append_audit_event(
            {
                **audit_base,
                "decision": "DENY",
                "deny_reason": f"prompt_too_large:{len(prompt_text)}>{max_prompt_chars}",
            }
        )
        raise HTTPException(
            status_code=403,
            detail=f"Execution denied: prompt too large ({len(prompt_text)} chars > {max_prompt_chars}).",
        )

    max_tokens_to_send = max_output_tokens if max_output_tokens > 0 else None

    # 5) Forward to model provider, then enforce cost ceiling (POST)
    try:
        result = await call_openai(request, max_tokens=max_tokens_to_send)
        output = result["content"]
        usage = result.get("usage", {}) or {}

        pricing = policy.get("pricing", {}) or {}
        max_cost = float(policy.get("max_cost_usd_per_request", 0.0) or 0.0)
        cost_usd = estimate_cost_usd(request.model, usage, pricing)

        if max_cost > 0 and cost_usd > max_cost:
            append_audit_event(
                {
                    **audit_base,
                    "decision": "DENY",
                    "deny_reason": f"cost_exceeded:{cost_usd:.6f}>{max_cost:.6f}",
                    "usage": usage,
                    "estimated_cost_usd": cost_usd,
                }
            )
            raise HTTPException(
                status_code=403,
                detail=f"Execution denied: cost ${cost_usd:.6f} exceeded max ${max_cost:.6f}.",
            )

        append_audit_event(
            {
                **audit_base,
                "decision": "ALLOW",
                "usage": usage,
                "estimated_cost_usd": cost_usd,
            }
        )

        return AIResponse(content=output)

    except HTTPException:
        raise
    except Exception as e:
        append_audit_event({**audit_base, "decision": "ERROR", "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# --- Core choke point (LLM + controlled action) ---
@app.post("/execute_action", response_model=AIResponse)
async def execute_action(
    request: AIRequest,
    http_request: Request,
    x_env: str = Header(default="dev"),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    """
    Same authority checks as /execute, but also executes a controlled action
    through a stubbed action executor (no external side effects), with approval modes,
    plus idempotency to prevent double execution.
    """
    env = x_env.strip().lower()

    request_id = str(uuid.uuid4())
    client_ip = http_request.client.host if http_request.client else None

    policy = load_policy()
    p_hash = policy_hash(policy)

    # Normalize idempotency key
    idempotency_key = (idempotency_key or "").strip()
    if idempotency_key:
        request.idempotency_key = idempotency_key

    audit_base = {
        "timestamp_utc": utc_now_iso(),
        "request_id": request_id,
        "client_ip": client_ip,
        "env": env,
        "model": request.model,
        "action_type": request.action_type,
        "policy_hash": p_hash,
        "endpoint": "/execute_action",
        "idempotency_key": idempotency_key or None,
    }

    # Require an action payload
    if request.action is None:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": "missing_action_payload"})
        raise HTTPException(status_code=400, detail="Missing action payload. Provide request.action.")

    action_payload = {"type": request.action.type, "params": request.action.params}
    action_fingerprint = fingerprint_action(env, request.action_type, action_payload)

    # Replay protection: return stored response if already seen for this key
    if idempotency_key:
        existing = idem_get(idempotency_key)
        if existing:
            stored_fingerprint, stored_payload = existing
            if stored_fingerprint != action_fingerprint:
                append_audit_event(
                    {**audit_base, "decision": "DENY", "deny_reason": "idempotency_key_reused_with_different_payload"}
                )
                raise HTTPException(status_code=409, detail="Idempotency-Key reuse detected with different payload.")

            append_audit_event({**audit_base, "decision": "ALLOW", "note": "idempotent_replay"})
            return AIResponse(**stored_payload)

    # Runtime denies
    if STATE.kill_switch:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": "kill_switch_enabled"})
        raise HTTPException(status_code=403, detail="Execution denied: kill switch is enabled.")

    if STATE.deny_prod and env == "prod":
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": "runtime_deny_prod"})
        raise HTTPException(status_code=403, detail="Execution denied: production calls are currently blocked.")

    # Policy allowlists
    allowed_envs = as_set(policy.get("allowed_envs"))
    allowed_models = as_set(policy.get("allowed_models"))
    allowed_action_types = as_set(policy.get("allowed_action_types"))
    deny_in_prod = bool(policy.get("deny_in_prod", False))

    if env not in allowed_envs:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": f"env_not_allowed:{env}"})
        raise HTTPException(status_code=403, detail=f"Execution denied: env '{env}' is not allowed by policy.")

    if request.model not in allowed_models:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": f"model_not_allowed:{request.model}"})
        raise HTTPException(status_code=403, detail=f"Execution denied: model '{request.model}' is not allowed by policy.")

    if request.action_type not in allowed_action_types:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": f"action_type_not_allowed:{request.action_type}"})
        raise HTTPException(
            status_code=403,
            detail=f"Execution denied: action_type '{request.action_type}' is not allowed by policy.",
        )

    if deny_in_prod and env == "prod":
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": "policy_deny_in_prod"})
        raise HTTPException(status_code=403, detail="Execution denied: policy denies all production execution.")

    # Executable actions allowlist (extra safety)
    executable_actions = as_set(policy.get("executable_actions", []))
    if request.action.type not in executable_actions:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": f"action_not_executable:{request.action.type}"})
        raise HTTPException(
            status_code=403,
            detail=f"Execution denied: action '{request.action.type}' is not allowed for execution by policy.",
        )

    # Determine approval mode (global + per-action override)
    approval_mode = str(policy.get("approval_mode", "auto_execute")).strip().lower()
    mode_overrides = policy.get("approval_mode_by_action", {}) or {}
    approval_mode = str(mode_overrides.get(request.action.type, approval_mode)).strip().lower()

    if approval_mode not in {"auto_execute", "require_human_approval", "simulation_only"}:
        append_audit_event({**audit_base, "decision": "DENY", "deny_reason": f"invalid_approval_mode:{approval_mode}"})
        raise HTTPException(status_code=500, detail=f"Invalid approval_mode in policy: {approval_mode}")

    # Pre cost guardrails
    max_prompt_chars = int(policy.get("max_prompt_chars", 0) or 0)
    max_output_tokens = int(policy.get("max_output_tokens", 0) or 0)

    prompt_text = "\n".join([m.content for m in request.messages])
    if max_prompt_chars > 0 and len(prompt_text) > max_prompt_chars:
        append_audit_event(
            {
                **audit_base,
                "decision": "DENY",
                "deny_reason": f"prompt_too_large:{len(prompt_text)}>{max_prompt_chars}",
            }
        )
        raise HTTPException(
            status_code=403,
            detail=f"Execution denied: prompt too large ({len(prompt_text)} chars > {max_prompt_chars}).",
        )

    max_tokens_to_send = max_output_tokens if max_output_tokens > 0 else None

    # Call LLM (decision support), enforce post-cost, then act based on approval mode
    try:
        llm_result = await call_openai(request, max_tokens=max_tokens_to_send)
        output = llm_result["content"]
        usage = llm_result.get("usage", {}) or {}

        pricing = policy.get("pricing", {}) or {}
        max_cost = float(policy.get("max_cost_usd_per_request", 0.0) or 0.0)
        cost_usd = estimate_cost_usd(request.model, usage, pricing)

        if max_cost > 0 and cost_usd > max_cost:
            append_audit_event(
                {
                    **audit_base,
                    "decision": "DENY",
                    "deny_reason": f"cost_exceeded:{cost_usd:.6f}>{max_cost:.6f}",
                    "usage": usage,
                    "estimated_cost_usd": cost_usd,
                }
            )
            raise HTTPException(
                status_code=403,
                detail=f"Execution denied: cost ${cost_usd:.6f} exceeded max ${max_cost:.6f}.",
            )

        # --- Approval mode branching ---
        if approval_mode == "simulation_only":
            response_payload = AIResponse(
                content=output,
                action_result=ActionResult(
                    executed=False,
                    action_type=request.action.type,
                    action_params=request.action.params,
                    execution_id="SIMULATION",
                    note="Simulation only: action not executed.",
                ),
                approval=ApprovalInfo(approval_mode="simulation_only"),
            )

            append_audit_event(
                {
                    **audit_base,
                    "decision": "ALLOW",
                    "note": "simulation_only",
                    "usage": usage,
                    "estimated_cost_usd": cost_usd,
                    "action": action_payload,
                }
            )

            if idempotency_key:
                put_if_absent(idempotency_key, action_fingerprint, response_payload.dict())

            return response_payload

        if approval_mode == "require_human_approval":
            approval = create_approval(
                env=env,
                model=request.model,
                action_type=request.action_type,
                action=action_payload,
                llm_output=output,
                usage=usage,
                estimated_cost_usd=cost_usd,
                policy_hash=p_hash,
                request_id=request_id,
                idempotency_key=idempotency_key or None,
            )

            response_payload = AIResponse(
                content=output,
                action_result=ActionResult(
                    executed=False,
                    action_type=request.action.type,
                    action_params=request.action.params,
                    execution_id=approval.approval_id,
                    note="Pending human approval: action not executed yet.",
                ),
                approval=ApprovalInfo(
                    approval_mode="require_human_approval",
                    approval_id=approval.approval_id,
                    status=approval.status,
                ),
            )

            append_audit_event(
                {
                    **audit_base,
                    "decision": "ALLOW",
                    "note": "created_approval_request",
                    "usage": usage,
                    "estimated_cost_usd": cost_usd,
                    "approval_id": approval.approval_id,
                    "action": action_payload,
                }
            )

            if idempotency_key:
                put_if_absent(idempotency_key, action_fingerprint, response_payload.dict())

            return response_payload

        # approval_mode == "auto_execute"
        try:
            exec_payload = execute_action_stub(request.action.type, request.action.params)
        except ActionExecutionError as ex:
            append_audit_event(
                {
                    **audit_base,
                    "decision": "DENY",
                    "deny_reason": f"action_executor_rejected:{str(ex)}",
                    "usage": usage,
                    "estimated_cost_usd": cost_usd,
                    "action": action_payload,
                }
            )
            raise HTTPException(status_code=403, detail=f"Action denied by executor: {str(ex)}")

        response_payload = AIResponse(
            content=output,
            action_result=ActionResult(**exec_payload),
            approval=ApprovalInfo(approval_mode="auto_execute"),
        )

        append_audit_event(
            {
                **audit_base,
                "decision": "ALLOW",
                "note": "auto_execute",
                "usage": usage,
                "estimated_cost_usd": cost_usd,
                "action": action_payload,
                "action_result": exec_payload,
            }
        )

        if idempotency_key:
            put_if_absent(idempotency_key, action_fingerprint, response_payload.dict())

        return response_payload

    except HTTPException:
        raise
    except Exception as e:
        append_audit_event({**audit_base, "decision": "ERROR", "error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

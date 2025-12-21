import uuid
from typing import Dict, Any


class ActionExecutionError(Exception):
    pass


def execute_action_stub(action_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stubbed executor. Does NOT call external systems.
    Returns a deterministic execution payload you can log and show.
    """

    execution_id = str(uuid.uuid4())

    # Simulate simple validation rules (MVP)
    if action_type == "customer_message":
        if "to" not in params or "message" not in params:
            raise ActionExecutionError("customer_message requires params: to, message")

    if action_type == "write_crm":
        if "object" not in params or "fields" not in params:
            raise ActionExecutionError("write_crm requires params: object, fields")

    if action_type == "refund":
        # We explicitly refuse refunds in stub unless you want to allow it
        raise ActionExecutionError("refund is not enabled in stub executor")

    # Return "executed" payload
    return {
        "executed": True,
        "action_type": action_type,
        "action_params": params,
        "execution_id": execution_id,
        "note": "Stub executor: no external side effects occurred.",
    }

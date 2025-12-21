from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class Message(BaseModel):
    role: str
    content: str


class ActionRequest(BaseModel):
    """
    Represents a real-world action the AI wants to execute.
    This is the thing that must be controlled.
    """
    type: str = Field(..., description="e.g., customer_message, write_crm, refund")
    params: Dict[str, Any] = Field(default_factory=dict)


class AIRequest(BaseModel):
    model: str
    messages: List[Message]
    temperature: Optional[float] = 0.7

    # High-level category enforced by policy (broad class)
    action_type: str = "read_only"

    # Concrete action payload for /execute_action (optional for /execute)
    action: Optional[ActionRequest] = None

    # Optional idempotency key (usually provided via Idempotency-Key header)
    idempotency_key: Optional[str] = None

    # Extra context (optional)
    metadata: Optional[Dict[str, Any]] = None


class ActionResult(BaseModel):
    executed: bool
    action_type: str
    action_params: Dict[str, Any]
    execution_id: str
    note: Optional[str] = None


class ApprovalInfo(BaseModel):
    approval_mode: str  # auto_execute | require_human_approval | simulation_only
    approval_id: Optional[str] = None
    status: Optional[str] = None  # PENDING | APPROVED | DENIED


class AIResponse(BaseModel):
    content: str
    action_result: Optional[ActionResult] = None
    approval: Optional[ApprovalInfo] = None

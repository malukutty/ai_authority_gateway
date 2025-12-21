AI Authority Gateway
---------------------------
A single choke point that controls, approves, audits, and enforces AI actions before they touch the real world.

The problem
----------------
AI systems are increasingly wired directly into production systems.

But there is no authority layer.

No approvals.
No cost ceilings.
No kill switch.
No idempotency.
No audit trail.

This is how companies end up with runaway costs, silent data corruption, duplicated actions, and irreversible mistakes.

What this is
----------------
AI Authority Gateway is an execution control plane for AI.

It sits between:

your application

your LLM

real-world systems (email, CRM, billing, etc.)

Nothing executes unless it passes policy.

This is not about better prompts.
This is about control.

What it enforces
-------------------------------
Out of the box, the gateway provides:

  Environment-based execution control (dev / prod)
  Global kill switch
  Policy-based allowlists (models, environments, action types)
  Cost ceilings (pre and post execution)
  Human approval workflows
  Simulation-only execution mode
  Idempotency (prevents double execution)
  Append-only audit log
  Every request flows through a single authority boundary.

What it is not
----------------------------
This project is not:

a chatbot framework
an agent playground
a prompt engineering tool
an orchestration library

It does not try to make AI “smarter”.
It makes AI safe to execute.

Mental model
---------------
Client
  ↓
AI Authority Gateway
  ↓ (allowed / approved)
LLM
  ↓ (controlled)
Action Executor


The gateway is the only place where execution decisions are made.

Key concepts
-----------------
Action vs decision

LLMs generate decisions.
The gateway controls actions.

An action is anything with side effects:

sending an email
writing to a CRM
issuing a refund
mutating production data

Decisions without authority are suggestions.
Actions require enforcement.

Approval modes

Each action can run in one of three modes:

auto_execute
Executes immediately if policy allows.

require_human_approval
Creates an approval request. Nothing executes until approved.

simulation_only
Runs the LLM, but never executes the action.

Approval modes can be set globally or per action type.

Idempotency

All action execution supports idempotency.

Same idempotency key + same payload → returns cached result
Same idempotency key + different payload → request denied

This prevents:

duplicate emails
duplicate CRM writes
replay attacks

This is the same safety model used by Stripe, AWS, and Kubernetes.

Audit log
-----------------
Every decision is recorded in an append-only audit log.

Each entry captures:

request id
environment
model
action type
decision (allow / deny / error)
reason
cost estimate
approval status
execution result

This is the system of record.

Current status
-----------------
This is an early infrastructure prototype.

Approvals are stored in memory
Idempotency is stored in memory
Executors are stubbed (no real side effects)


Why this exists
-----------------------
Every major infrastructure shift creates a missing control layer.

Finance → ledgers
Cloud → IAM
Payments → Stripe
CI/CD → deployment gates

AI currently has none.

This project explores what an authority layer for AI execution should look like.

Who this is for
--------------------
This is for:

infra engineers
platform teams
security and compliance teams
founders wiring AI into production systems

If you are building “AI agents” that can act, this problem will eventually find you.

***Not production-ready (yet)
This repository is intentionally minimal.***

Persistence, durability, and real executors are future work.
Those are solvable problems once the control surface is correct.


If you’ve thought about:

approvals for AI
safe execution
AI cost containment
agent control planes

I’d love to hear how you’re approaching it.

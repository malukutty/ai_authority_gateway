import type { Commitment } from "../../core/types.js";
import type { PolicyConfig } from "../../core/policy.js";
import { evaluate } from "../../core/evaluate.js";
import { writeAudit } from "../../core/audit.js";

export async function authorityShopifyRefund(params: {
  shopDomain: string;
  accessToken: string;
  orderId: string;

  amountCents: number;
  currency: string;

  actorLane: Commitment["actorLane"];
  role?: Commitment["role"];
  customerId?: string;

  policy: PolicyConfig;
  simulate?: boolean;
}) {
  const commitment: Commitment = {
    type: "refund",
    env: "prod",
    actorLane: params.actorLane,
    role: params.role,
    amountCents: params.amountCents,
    currency: params.currency,
    orderId: params.orderId,
    customerId: params.customerId,
  };

  const decision = evaluate(commitment, params.policy);

  writeAudit({
    ts: Date.now(),
    commitment,
    decision,
  });

  if (decision.status !== "allow") {
    return { blocked: true, decision };
  }

  if (params.simulate) {
    return {
      blocked: false,
      simulated: true,
      decision,
      shopifyResponse: { ok: true },
    };
  }

  return {
    blocked: false,
    decision,
    note: "Allowed. Execute refund via Shopify client in your app.",
  };
}
import { evaluate } from "../../core/evaluate.js";
import { writeAudit } from "../../core/audit.js";
export async function authorityShopifyRefund(params) {
    const commitment = {
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
//# sourceMappingURL=refund.js.map
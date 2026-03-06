import type { Commitment } from "../../core/types.js";
import type { PolicyConfig } from "../../core/policy.js";
export declare function authorityShopifyRefund(params: {
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
}): Promise<{
    blocked: boolean;
    decision: import("../../core/types.js").Decision;
    simulated?: undefined;
    shopifyResponse?: undefined;
    note?: undefined;
} | {
    blocked: boolean;
    simulated: boolean;
    decision: import("../../core/types.js").Decision;
    shopifyResponse: {
        ok: boolean;
    };
    note?: undefined;
} | {
    blocked: boolean;
    decision: import("../../core/types.js").Decision;
    note: string;
    simulated?: undefined;
    shopifyResponse?: undefined;
}>;
//# sourceMappingURL=refund.d.ts.map
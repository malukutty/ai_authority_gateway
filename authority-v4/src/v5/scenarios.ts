export type DemoScenario = {
  id: string;
  label: string;
  customerMessage: string;
};

export const DEMO_SCENARIOS: DemoScenario[] = [
  {
    id: "refund_request",
    label: "Refund request",
    customerMessage: "I want a refund for my last charge."
  },
  {
    id: "invoice_waiver",
    label: "Invoice waiver",
    customerMessage: "Can you waive this invoice since the service had issues?"
  },
  {
    id: "subscription_extension",
    label: "Subscription extension",
    customerMessage: "Can you extend my trial by 30 days?"
  },
  {
    id: "delivery_guarantee",
    label: "Delivery guarantee",
    customerMessage: "Can you confirm this will definitely be resolved by Friday?"
  },
  {
    id: "compensation_request",
    label: "Compensation request",
    customerMessage: "I've had repeated issues. Can you offer account credit?"
  },
  {
    id: "general_support",
    label: "General support question",
    customerMessage: "How do I update my billing details?"
  }
];
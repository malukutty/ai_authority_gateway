function includesAny(text: string, patterns: RegExp[]) {
  return patterns.some((p) => p.test(text));
}

export function buildAssistantDraft(customerMessage: string): string {
  const text = customerMessage.trim();

  if (!text) {
    return "I’m here to help. Could you share a bit more about the issue?";
  }

  const refundPatterns = [
    /\brefund\b/i,
    /money back/i,
    /charge back/i,
    /charged/i
  ];

  const creditPatterns = [
    /\bcredit\b/i,
    /compensation/i,
    /account credit/i
  ];

  const waiverPatterns = [
    /\bwaive\b/i,
    /\bwaiver\b/i,
    /waive this invoice/i,
    /waive the invoice/i,
    /write\s*off/i,
    /remove\s*charge/i,
    /cancel\s*charge/i,
    /adjust\s*invoice/i,
    /billing adjustment/i
  ];

  const extensionPatterns = [
    /extend/i,
    /trial/i,
    /subscription/i
  ];

  const guaranteePatterns = [
    /\bguarantee\b/i,
    /\bdefinitely\b/i,
    /\bpromise\b/i,
    /by friday/i,
    /by monday/i,
    /resolved by/i,
    /confirm .* will/i
  ];

  const harmlessBillingPatterns = [
    /billing details/i,
    /update .* billing/i,
    /change .* billing/i,
    /payment method/i,
    /invoice history/i,
    /billing address/i
  ];

  if (includesAny(text, harmlessBillingPatterns)) {
    return "You can update your billing details from your account settings. If you want, I can guide you to the right place.";
  }

  if (includesAny(text, refundPatterns)) {
    return "I can issue a refund for this inconvenience.";
  }

  if (includesAny(text, creditPatterns)) {
    return "I can apply account credit to make up for this experience.";
  }

  if (includesAny(text, waiverPatterns)) {
    return "I can waive this invoice and help resolve this for you.";
  }

  if (includesAny(text, extensionPatterns)) {
    return "I can extend your subscription period to help make this right.";
  }

  if (includesAny(text, guaranteePatterns)) {
    return "I can confirm this will be resolved by Friday.";
  }

  return "I’m happy to help with that. Let me look into it and share the best next step.";
}
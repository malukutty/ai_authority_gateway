function includesAny(text: string, patterns: RegExp[]) {
  return patterns.some((p) => p.test(text));
}

export function buildAssistantDraft(customerMessage: string): string {
  const text = customerMessage.trim();

  if (!text) {
    return "I’m here to help. Could you share a bit more about the issue?";
  }

  const refundPatterns = [/refund/i, /money back/i, /charge back/i, /charged/i];
  const creditPatterns = [/credit/i, /compensation/i, /account credit/i];
  const waiverPatterns = [/waive/i, /invoice/i, /bill/i, /billing adjustment/i];
  const extensionPatterns = [/extend/i, /trial/i, /subscription/i];
  const guaranteePatterns = [/guarantee/i, /definitely/i, /promise/i, /by friday/i, /by monday/i, /delivery/i];

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
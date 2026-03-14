import type { DetectedCommitment } from "./types.js";

const REFUND_PATTERNS = [
  /\brefund\b/i,
  /issue a refund/i,
  /full refund/i,
  /partial refund/i,
  /money back/i
];

const CREDIT_PATTERNS = [
  /\bcredit\b/i,
  /account credit/i,
  /apply credit/i,
  /store credit/i,
  /offer .* credit/i
];

const UNKNOWN_COMMITMENT_PATTERNS = [
  /\bwaive\b/i,
  /\bdiscount\b/i,
  /billing adjustment/i,
  /adjust the invoice/i,
  /extend .*trial/i,
  /extend .*subscription/i,
  /\bguarantee\b/i,
  /\bpromise\b/i,
  /confirm .* by friday/i,
  /confirm .* by monday/i
];

function findEvidence(text: string, patterns: RegExp[]): string[] {
  const hits = new Set<string>();

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[0]) {
      hits.add(match[0]);
    }
  }

  return Array.from(hits);
}

function extractAmountCents(text: string): number | undefined {
  const moneyMatch = text.match(/\$?\s?(\d{1,7})(?:\.(\d{1,2}))?/);
  if (!moneyMatch) return undefined;

  const dollars = Number(moneyMatch[1] ?? "0");
  const centsPart = (moneyMatch[2] ?? "").padEnd(2, "0").slice(0, 2);
  const cents = Number(centsPart || "0");

  if (!Number.isFinite(dollars) || !Number.isFinite(cents)) return undefined;
  return dollars * 100 + cents;
}

export function detectCommitment(
  assistantDraft: string,
  customerMessage: string
): DetectedCommitment {
  const text = `${customerMessage}\n${assistantDraft}`;

  const refundEvidence = findEvidence(text, REFUND_PATTERNS);
  if (refundEvidence.length > 0) {
    return {
      detected: true,
      type: "refund",
      evidencePhrases: refundEvidence,
      amountCents: extractAmountCents(text),
      currency: "usd",
      confidence: 0.93
    };
  }

  const creditEvidence = findEvidence(text, CREDIT_PATTERNS);
  if (creditEvidence.length > 0) {
    return {
      detected: true,
      type: "credit",
      evidencePhrases: creditEvidence,
      amountCents: extractAmountCents(text),
      currency: "usd",
      confidence: 0.9
    };
  }

  const unknownEvidence = findEvidence(text, UNKNOWN_COMMITMENT_PATTERNS);
  if (unknownEvidence.length > 0) {
    return {
      detected: true,
      type: "unknown",
      evidencePhrases: unknownEvidence,
      amountCents: extractAmountCents(text),
      currency: "usd",
      confidence: 0.74
    };
  }

  return {
    detected: false,
    type: "unknown",
    evidencePhrases: [],
    confidence: 0.04
  };
}
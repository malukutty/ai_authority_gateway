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
  /offer .* credit/i,
  /compensation/i
];

const WAIVER_PATTERNS = [
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

const PROMISE_PATTERNS = [
  /\bguarantee\b/i,
  /\bpromise\b/i,
  /confirm .* will/i,
  /will be resolved by/i,
  /will definitely be/i,
  /assure you/i,
  /ensure .* will/i
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
  const extractedAmount = extractAmountCents(text);

  const refundEvidence = findEvidence(text, REFUND_PATTERNS);
  if (refundEvidence.length > 0) {
    return {
      detected: true,
      type: "refund",
      evidencePhrases: refundEvidence,
      amountCents: extractedAmount,
      amountKnown: extractedAmount !== undefined,
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
      amountCents: extractedAmount,
      amountKnown: extractedAmount !== undefined,
      currency: "usd",
      confidence: 0.9
    };
  }

  const waiverEvidence = findEvidence(text, WAIVER_PATTERNS);
  if (waiverEvidence.length > 0) {
    return {
      detected: true,
      type: "credit",
      evidencePhrases: waiverEvidence,
      amountCents: extractedAmount,
      amountKnown: extractedAmount !== undefined,
      currency: "usd",
      confidence: 0.91
    };
  }

  const promiseEvidence = findEvidence(text, PROMISE_PATTERNS);
  if (promiseEvidence.length > 0) {
    return {
      detected: true,
      type: "unknown",
      evidencePhrases: promiseEvidence,
      amountKnown: false,
      confidence: 0.82
    };
  }

  return {
    detected: false,
    type: "unknown",
    evidencePhrases: [],
    amountKnown: false,
    confidence: 0.04
  };
} 
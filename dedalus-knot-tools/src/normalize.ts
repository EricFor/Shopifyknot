import { PurchasePoint, SeasonName } from "./types.js";

const DATE_KEYS = [
  "timestamp",
  "purchase_timestamp",
  "purchase_time",
  "purchase_date",
  "transaction_time",
  "transaction_date",
  "created_at",
  "createdAt",
  "date",
  "time",
];

const AMOUNT_KEYS = [
  "amount",
  "purchase_amount",
  "transaction_amount",
  "subtotal",
  "total",
  "value",
];

function toNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const cleaned = value.replace(/[^0-9.\-]/g, "");
    if (!cleaned) return null;
    const parsed = Number(cleaned);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (typeof value === "object" && value !== null) {
    const asRecord = value as Record<string, unknown>;
    if ("value" in asRecord) return toNumber(asRecord.value);
    if ("amount" in asRecord) return toNumber(asRecord.amount);
  }
  return null;
}

function asIsoOrNull(input: unknown): string | null {
  if (input instanceof Date) return Number.isNaN(input.getTime()) ? null : input.toISOString();
  if (typeof input !== "string" && typeof input !== "number") return null;
  const date = new Date(input);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function findFirstDate(obj: Record<string, unknown>): string | null {
  for (const key of DATE_KEYS) {
    if (key in obj) {
      const parsed = asIsoOrNull(obj[key]);
      if (parsed) return parsed;
    }
  }
  return null;
}

function findFirstAmount(obj: Record<string, unknown>): number | null {
  for (const key of AMOUNT_KEYS) {
    if (key in obj) {
      const amount = toNumber(obj[key]);
      if (amount !== null) return amount;
    }
  }
  return null;
}

function extractCandidateArray(input: unknown): unknown[] {
  if (Array.isArray(input)) return input;
  if (typeof input !== "object" || input === null) return [];

  const obj = input as Record<string, unknown>;
  const preferredArrays = ["purchases", "transactions", "items", "data", "results"];
  for (const key of preferredArrays) {
    if (Array.isArray(obj[key])) return obj[key] as unknown[];
  }

  for (const value of Object.values(obj)) {
    if (Array.isArray(value)) return value;
  }

  return [];
}

export function normalizeKnotPurchases(knotData: unknown): PurchasePoint[] {
  const source = extractCandidateArray(knotData);
  const normalized: PurchasePoint[] = [];

  for (const item of source) {
    if (typeof item !== "object" || item === null) continue;
    const record = item as Record<string, unknown>;

    const timestamp = findFirstDate(record);
    const amount = findFirstAmount(record);
    if (!timestamp || amount === null) continue;

    normalized.push({ timestamp, amount, raw: item });
  }

  return normalized.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

export function inDateRange(isoTimestamp: string, date1: string, date2: string): boolean {
  const t = new Date(isoTimestamp).getTime();
  const start = new Date(date1).getTime();
  const end = new Date(date2).getTime();
  if (Number.isNaN(t) || Number.isNaN(start) || Number.isNaN(end)) return false;
  return t >= Math.min(start, end) && t <= Math.max(start, end);
}

export function getSeason(isoTimestamp: string): SeasonName {
  const month = new Date(isoTimestamp).getUTCMonth() + 1;
  if (month === 12 || month <= 2) return "winter";
  if (month <= 5) return "spring";
  if (month <= 8) return "summer";
  return "fall";
}

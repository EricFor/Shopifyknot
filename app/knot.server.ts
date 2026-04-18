const KNOT_BASE_URL = process.env.KNOT_BASE_URL || "https://development.knotapi.com";
const KNOT_CLIENT_ID = process.env.KNOT_CLIENT_ID || "";
const KNOT_SECRET = process.env.KNOT_SECRET || "";
const KNOT_ENVIRONMENT = process.env.KNOT_ENVIRONMENT || "development";
const KNOT_PRODUCT_TYPE = process.env.KNOT_PRODUCT_TYPE || "transaction_link";
const DEFAULT_DISCOUNT_PREFIX = process.env.KNOT_DISCOUNT_PREFIX || "AMZ5";

function getAuthHeader() {
  if (!KNOT_CLIENT_ID || !KNOT_SECRET) {
    throw new Error("KNOT_CLIENT_ID and KNOT_SECRET must be set on the server.");
  }

  const encoded = Buffer.from(`${KNOT_CLIENT_ID}:${KNOT_SECRET}`).toString("base64");
  return `Basic ${encoded}`;
}

async function knotFetch(path: string, init: RequestInit = {}) {
  const response = await fetch(`${KNOT_BASE_URL}${path}`, {
    ...init,
    headers: {
      Authorization: getAuthHeader(),
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Knot request failed (${response.status}): ${errorBody}`);
  }

  return response;
}

export type KnotCreateSessionInput = {
  externalUserId: string;
  email?: string | null;
  phoneNumber?: string | null;
  metadata?: Record<string, string>;
};

export async function createKnotSession(input: KnotCreateSessionInput) {
  const response = await knotFetch("/session/create", {
    method: "POST",
    body: JSON.stringify({
      type: KNOT_PRODUCT_TYPE,
      external_user_id: input.externalUserId,
      email: input.email || null,
      phone_number: input.phoneNumber || null,
      metadata: input.metadata || undefined,
    }),
  });

  const data = (await response.json()) as { session: string };
  return data.session;
}

type KnotMerchant = {
  id: number;
  name: string;
  category?: string;
  logo?: string;
};

export async function findMerchantByName(name: string) {
  const response = await knotFetch("/merchant/list", {
    method: "POST",
    body: JSON.stringify({
      type: KNOT_PRODUCT_TYPE,
      platform: "web",
      search: name,
    }),
  });

  const merchants = (await response.json()) as KnotMerchant[] | KnotMerchant;
  const list = Array.isArray(merchants) ? merchants : [merchants];

  return list.find((merchant) => merchant.name?.toLowerCase().includes(name.toLowerCase()));
}

export async function getMerchantAccounts(externalUserId: string, merchantId?: number) {
  const params = new URLSearchParams({
    external_user_id: externalUserId,
  });

  if (merchantId) params.set("merchant_id", String(merchantId));
  params.set("type", KNOT_PRODUCT_TYPE);

  const response = await knotFetch(`/accounts/get?${params.toString()}`, {
    method: "GET",
    headers: {
      Authorization: getAuthHeader(),
    },
  });

  return response.json();
}

export function getKnotPublicConfig() {
  return {
    clientId: KNOT_CLIENT_ID,
    environment: KNOT_ENVIRONMENT,
    productType: KNOT_PRODUCT_TYPE,
  };
}

export function getKnotRuntimeConfigStatus() {
  return {
    environment: KNOT_ENVIRONMENT,
    baseUrl: KNOT_BASE_URL,
    hasClientId: Boolean(KNOT_CLIENT_ID),
    hasSecret: Boolean(KNOT_SECRET),
    productType: KNOT_PRODUCT_TYPE,
  };
}

export function getKnotSecret() {
  return KNOT_SECRET;
}

export function makeDiscountCode(externalUserId: string) {
  const normalized = externalUserId.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
  const suffix = normalized.slice(-6) || Math.random().toString(36).slice(2, 8).toUpperCase();
  return `${DEFAULT_DISCOUNT_PREFIX}-${suffix}`;
}

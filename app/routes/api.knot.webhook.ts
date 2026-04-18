import crypto from "node:crypto";
import type { ActionFunctionArgs } from "react-router";
import prisma from "../db.server";
import { getKnotSecret, makeDiscountCode } from "../knot.server";

type KnotWebhookPayload = {
  event?: string;
  session_id?: string;
  task_id?: number;
  external_user_id?: string;
  merchant?: {
    id?: number;
    name?: string;
  };
  timestamp?: number;
  data?: Record<string, unknown>;
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Knot-Signature,Encryption-Type",
  };
}

function buildEventKey(payload: KnotWebhookPayload) {
  return [
    payload.event || "UNKNOWN",
    payload.task_id ?? "na",
    payload.external_user_id ?? "na",
    payload.timestamp ?? "na",
    payload.merchant?.id ?? "na",
  ].join("|");
}

function computeKnotSignature(request: Request, payload: KnotWebhookPayload) {
  const contentLength = request.headers.get("content-length") || "";
  const contentType = request.headers.get("content-type") || "";
  const encryptionType = request.headers.get("encryption-type") || "";
  const event = payload.event || "";
  const sessionId = payload.session_id;

  const parts = [
    "Content-Length",
    contentLength,
    "Content-Type",
    contentType,
    "Encryption-Type",
    encryptionType,
    "event",
    event,
  ];

  if (sessionId) {
    parts.push("session_id", sessionId);
  }

  const stringToSign = parts.join("|");
  return crypto.createHmac("sha256", getKnotSecret()).update(stringToSign).digest("base64");
}

function safeEqualBase64(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

async function issueDiscountIfNeeded(payload: KnotWebhookPayload, eventKey: string) {
  const externalUserId = payload.external_user_id;
  if (!externalUserId) return null;

  const merchantId = payload.merchant?.id ?? null;
  const merchantName = payload.merchant?.name ?? null;

  const existing = await prisma.discountGrant.findFirst(
    merchantId === null
      ? {
          where: {
            externalUserId,
            merchantId: null,
          },
        }
      : {
          where: {
            externalUserId,
            merchantId,
          },
        },
  );

  if (existing) return existing;

  return prisma.discountGrant.create({
    data: {
      externalUserId,
      merchantId,
      merchantName,
      discountCode: makeDiscountCode(externalUserId),
      eventKey,
    },
  });
}

export const loader = async () =>
  new Response(null, {
    status: 405,
    headers: corsHeaders(),
  });

export const action = async ({ request }: ActionFunctionArgs) => {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  try {
    const rawBody = await request.text();
    const payload = JSON.parse(rawBody) as KnotWebhookPayload;
    const providedSignature = request.headers.get("knot-signature");

    if (providedSignature) {
      const expectedSignature = computeKnotSignature(request, payload);
      if (!safeEqualBase64(providedSignature, expectedSignature)) {
        return Response.json(
          { error: "Invalid Knot signature" },
          { status: 401, headers: corsHeaders() },
        );
      }
    }

    const eventKey = buildEventKey(payload);

    await prisma.knotWebhookEvent.upsert({
      where: { eventKey },
      create: {
        eventKey,
        event: payload.event || "UNKNOWN",
        externalUserId: payload.external_user_id || null,
        sessionId: payload.session_id || null,
        taskId: payload.task_id || null,
        merchantId: payload.merchant?.id || null,
        merchantName: payload.merchant?.name || null,
        timestampMs: payload.timestamp || null,
        payloadJson: rawBody,
      },
      update: {},
    });

    let discount = null;
    if (payload.event === "AUTHENTICATED") {
      discount = await issueDiscountIfNeeded(payload, eventKey);
    }

    return Response.json(
      {
        ok: true,
        event: payload.event || "UNKNOWN",
        issuedDiscountCode: discount?.discountCode || null,
      },
      { headers: corsHeaders() },
    );
  } catch (error) {
    return Response.json(
      {
        error: "Failed to process Knot webhook",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500, headers: corsHeaders() },
    );
  }
};

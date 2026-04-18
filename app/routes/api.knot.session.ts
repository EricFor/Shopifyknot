import type { ActionFunctionArgs } from "react-router";
import { createKnotSession, findMerchantByName, getKnotPublicConfig } from "../knot.server";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export const loader = async () => {
  return new Response(null, {
    status: 405,
    headers: corsHeaders(),
  });
};

export const action = async ({ request }: ActionFunctionArgs) => {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  try {
    const body = (await request.json()) as {
      externalUserId?: string;
      email?: string;
      phoneNumber?: string;
      shopDomain?: string;
      returnUrl?: string;
    };

    const shopDomain = body.shopDomain || "storefront";
    const externalUserId =
      body.externalUserId ||
      `${shopDomain}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

    const sessionId = await createKnotSession({
      externalUserId,
      email: body.email || null,
      phoneNumber: body.phoneNumber || null,
      metadata: {
        source: "amazon_store_popup",
        shop_domain: shopDomain,
      },
    });

    const amazonMerchant = await findMerchantByName("Amazon");
    const knot = getKnotPublicConfig();
    if (!knot.clientId) {
      throw new Error("KNOT_CLIENT_ID is missing on the server.");
    }

    return Response.json(
      {
        sessionId,
        externalUserId,
        merchantIds: amazonMerchant ? [amazonMerchant.id] : undefined,
        merchantName: amazonMerchant?.name || "Amazon",
        clientId: knot.clientId,
        environment: knot.environment,
        returnUrl: body.returnUrl || null,
      },
      { headers: corsHeaders() },
    );
  } catch (error) {
    return Response.json(
      {
        error: "Failed to create Knot session.",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      {
        status: 500,
        headers: corsHeaders(),
      },
    );
  }
};

import type { ActionFunctionArgs } from "react-router";
import { authenticate } from "../shopify.server";
import {
  createKnotSession,
  findMerchantByName,
  getKnotPublicConfig,
  getKnotRuntimeConfigStatus,
} from "../knot.server";

export const loader = async () => new Response(null, { status: 405 });

export const action = async ({ request }: ActionFunctionArgs) => {
  if (request.method !== "POST") {
    return new Response(null, { status: 405 });
  }

  try {
    await authenticate.public.appProxy(request);
  } catch (error) {
    if (error instanceof Response) {
      return Response.json(
        {
          error: "App proxy authentication failed.",
          details: `Status ${error.status}${error.statusText ? ` (${error.statusText})` : ""}. Ensure app proxy is configured and app is installed on this store.`,
        },
        { status: error.status || 401 },
      );
    }

    return Response.json(
      {
        error: "App proxy authentication failed.",
        details: error instanceof Error ? error.message : "Unknown app proxy error",
      },
      { status: 500 },
    );
  }

  try {
    const knotRuntime = getKnotRuntimeConfigStatus();
    if (!knotRuntime.hasClientId || !knotRuntime.hasSecret) {
      return Response.json(
        {
          error: "Knot credentials are missing on server.",
          details:
            "Set KNOT_CLIENT_ID and KNOT_SECRET in your app environment, then restart the dev server.",
          runtime: knotRuntime,
        },
        { status: 500 },
      );
    }

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

    return Response.json({
      sessionId,
      externalUserId,
      merchantIds: amazonMerchant ? [amazonMerchant.id] : undefined,
      merchantName: amazonMerchant?.name || "Amazon",
      clientId: knot.clientId,
      environment: knot.environment,
      runtime: knotRuntime,
      returnUrl: body.returnUrl || null,
    });
  } catch (error) {
    return Response.json(
      {
        error: "Failed to create Knot session.",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
};

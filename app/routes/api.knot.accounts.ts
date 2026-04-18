import type { LoaderFunctionArgs } from "react-router";
import { findMerchantByName, getMerchantAccounts } from "../knot.server";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export const action = async () => {
  return new Response(null, {
    status: 405,
    headers: corsHeaders(),
  });
};

export const loader = async ({ request }: LoaderFunctionArgs) => {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  try {
    const url = new URL(request.url);
    const externalUserId = url.searchParams.get("externalUserId");
    const explicitMerchantId = url.searchParams.get("merchantId");
    const merchantName = url.searchParams.get("merchantName") || "Amazon";

    if (!externalUserId) {
      return Response.json(
        { error: "externalUserId is required." },
        {
          status: 400,
          headers: corsHeaders(),
        },
      );
    }

    let merchantId = explicitMerchantId ? Number(explicitMerchantId) : undefined;
    if (!merchantId && merchantName) {
      const merchant = await findMerchantByName(merchantName);
      merchantId = merchant?.id;
    }

    const accounts = await getMerchantAccounts(externalUserId, merchantId);

    return Response.json(
      {
        externalUserId,
        merchantId: merchantId || null,
        accounts,
      },
      {
        headers: corsHeaders(),
      },
    );
  } catch (error) {
    return Response.json(
      {
        error: "Failed to fetch Knot account data.",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      {
        status: 500,
        headers: corsHeaders(),
      },
    );
  }
};

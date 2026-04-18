import type { LoaderFunctionArgs } from "react-router";
import { authenticate } from "../shopify.server";
import { findMerchantByName, getMerchantAccounts } from "../knot.server";

export const action = async () => new Response(null, { status: 405 });

export const loader = async ({ request }: LoaderFunctionArgs) => {
  await authenticate.public.appProxy(request);

  try {
    const url = new URL(request.url);
    const externalUserId = url.searchParams.get("externalUserId");
    const explicitMerchantId = url.searchParams.get("merchantId");
    const merchantName = url.searchParams.get("merchantName") || "Amazon";

    if (!externalUserId) {
      return Response.json({ error: "externalUserId is required." }, { status: 400 });
    }

    let merchantId = explicitMerchantId ? Number(explicitMerchantId) : undefined;
    if (!merchantId && merchantName) {
      const merchant = await findMerchantByName(merchantName);
      merchantId = merchant?.id;
    }

    const accounts = await getMerchantAccounts(externalUserId, merchantId);

    return Response.json({
      externalUserId,
      merchantId: merchantId || null,
      accounts,
    });
  } catch (error) {
    return Response.json(
      {
        error: "Failed to fetch Knot account data.",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
};

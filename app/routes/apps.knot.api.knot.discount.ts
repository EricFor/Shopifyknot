import type { LoaderFunctionArgs } from "react-router";
import { authenticate } from "../shopify.server";
import prisma from "../db.server";

export const action = async () => new Response(null, { status: 405 });

export const loader = async ({ request }: LoaderFunctionArgs) => {
  await authenticate.public.appProxy(request);

  try {
    const url = new URL(request.url);
    const externalUserId = url.searchParams.get("externalUserId");

    if (!externalUserId) {
      return Response.json({ error: "externalUserId is required." }, { status: 400 });
    }

    const grant = await prisma.discountGrant.findFirst({
      where: { externalUserId },
      orderBy: { issuedAt: "desc" },
    });

    return Response.json({
      externalUserId,
      discountCode: grant?.discountCode || null,
      issuedAt: grant?.issuedAt || null,
    });
  } catch (error) {
    return Response.json(
      {
        error: "Failed to fetch discount grant",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
};

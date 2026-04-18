import type { LoaderFunctionArgs } from "react-router";
import prisma from "../db.server";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export const action = async () =>
  new Response(null, {
    status: 405,
    headers: corsHeaders(),
  });

export const loader = async ({ request }: LoaderFunctionArgs) => {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  try {
    const url = new URL(request.url);
    const externalUserId = url.searchParams.get("externalUserId");

    if (!externalUserId) {
      return Response.json(
        { error: "externalUserId is required." },
        { status: 400, headers: corsHeaders() },
      );
    }

    const grant = await prisma.discountGrant.findFirst({
      where: { externalUserId },
      orderBy: { issuedAt: "desc" },
    });

    return Response.json(
      {
        externalUserId,
        discountCode: grant?.discountCode || null,
        issuedAt: grant?.issuedAt || null,
      },
      { headers: corsHeaders() },
    );
  } catch (error) {
    return Response.json(
      {
        error: "Failed to fetch discount grant",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500, headers: corsHeaders() },
    );
  }
};

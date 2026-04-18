import type { HeadersFunction, LoaderFunctionArgs } from "react-router";
import { useLoaderData } from "react-router";
import { boundary } from "@shopify/shopify-app-react-router/server";
import prisma from "../db.server";
import { authenticate } from "../shopify.server";

export const loader = async ({ request }: LoaderFunctionArgs) => {
  await authenticate.admin(request);

  const now = new Date();
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const [totalEvents, authenticatedEvents, totalDiscounts, recentEvents, recentDiscounts, events7d, authenticated7d] =
    await Promise.all([
      prisma.knotWebhookEvent.count(),
      prisma.knotWebhookEvent.count({ where: { event: "AUTHENTICATED" } }),
      prisma.discountGrant.count(),
      prisma.knotWebhookEvent.findMany({
        orderBy: { createdAt: "desc" },
        take: 12,
      }),
      prisma.discountGrant.findMany({
        orderBy: { issuedAt: "desc" },
        take: 12,
      }),
      prisma.knotWebhookEvent.count({ where: { createdAt: { gte: sevenDaysAgo } } }),
      prisma.knotWebhookEvent.count({
        where: { event: "AUTHENTICATED", createdAt: { gte: sevenDaysAgo } },
      }),
    ]);

  const conversionRate = totalEvents ? Math.round((authenticatedEvents / totalEvents) * 100) : 0;
  const conversionRate7d = events7d ? Math.round((authenticated7d / events7d) * 100) : 0;

  return {
    stats: {
      totalEvents,
      authenticatedEvents,
      totalDiscounts,
      conversionRate,
      events7d,
      authenticated7d,
      conversionRate7d,
    },
    recentEvents: recentEvents.map((event) => ({
      id: event.id,
      event: event.event,
      externalUserId: event.externalUserId,
      merchantName: event.merchantName,
      createdAt: event.createdAt.toISOString(),
    })),
    recentDiscounts: recentDiscounts.map((discount) => ({
      id: discount.id,
      externalUserId: discount.externalUserId,
      merchantName: discount.merchantName,
      discountCode: discount.discountCode,
      issuedAt: discount.issuedAt.toISOString(),
    })),
  };
};

function StatCard({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string | number;
  tone?: "default" | "success";
}) {
  return (
    <s-box
      padding="base"
      borderWidth="base"
      borderRadius="large"
      background={tone === "success" ? "success-subdued" : "subdued"}
    >
      <s-stack direction="block" gap="tight">
        <s-text>{label}</s-text>
        <s-heading>{value}</s-heading>
      </s-stack>
    </s-box>
  );
}

export default function KnotDashboardPage() {
  const data = useLoaderData<typeof loader>();

  return (
    <s-page heading="Knot Dashboard (WIP)">
      <s-section heading="Overview">
        <s-stack direction="inline" gap="base">
          <StatCard label="Total Webhook Events" value={data.stats.totalEvents} />
          <StatCard label="Authenticated Events" value={data.stats.authenticatedEvents} tone="success" />
          <StatCard label="Discounts Issued" value={data.stats.totalDiscounts} tone="success" />
          <StatCard label="Auth Conversion" value={`${data.stats.conversionRate}%`} />
        </s-stack>
      </s-section>

      <s-section heading="Last 7 Days">
        <s-stack direction="inline" gap="base">
          <StatCard label="Events (7d)" value={data.stats.events7d} />
          <StatCard label="Authenticated (7d)" value={data.stats.authenticated7d} tone="success" />
          <StatCard label="Conversion (7d)" value={`${data.stats.conversionRate7d}%`} />
        </s-stack>
      </s-section>

      <s-section heading="Recent Webhook Events">
        <s-box padding="base" borderWidth="base" borderRadius="base" background="subdued">
          <pre style={{ margin: 0, maxHeight: 280, overflow: "auto" }}>
            <code>{JSON.stringify(data.recentEvents, null, 2)}</code>
          </pre>
        </s-box>
      </s-section>

      <s-section heading="Recent Discount Grants">
        <s-box padding="base" borderWidth="base" borderRadius="base" background="subdued">
          <pre style={{ margin: 0, maxHeight: 280, overflow: "auto" }}>
            <code>{JSON.stringify(data.recentDiscounts, null, 2)}</code>
          </pre>
        </s-box>
      </s-section>

      <s-section slot="aside" heading="Notes">
        <s-unordered-list>
          <s-list-item>Webhook retries are deduped via an event key.</s-list-item>
          <s-list-item>Discount codes are generated when AUTHENTICATED webhook lands.</s-list-item>
          <s-list-item>Next step: chart views + per-merchant breakdown.</s-list-item>
        </s-unordered-list>
      </s-section>
    </s-page>
  );
}

export const headers: HeadersFunction = (headersArgs) => {
  return boundary.headers(headersArgs);
};

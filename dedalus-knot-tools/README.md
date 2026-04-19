# Dedalus Knot Tools

Standalone Dedalus SDK tools for Knot purchase analytics.

## What this includes

1. `computePurchaseStatsByPeriod`
- Computes `mean`, `std`, `min`, `max`, `range`, and `count` for `date1` to `date2`.
- Returns:
  - Year total over the requested range.
  - Seasonal totals (`winter`, `spring`, `summer`, `fall`).
- Empty period behavior:
  - `no purchases between date1-date2`
  - `no purchases in the year`
  - `no purchases in the season`

2. `computePurchaseTimeDistribution`
- Computes distribution of purchase timing for `date1` to `date2`.
- Returns buckets for:
  - `byDayOfWeek`
  - `byHourOfDay`
  - `byWeekOfYear`
  - `byMonth`
  - `byDayOfMonth`
- Also returns:
  - `mostLikelyDayOfWeek`
  - `leastLikelyDayOfWeek`
- Includes year total + seasonal breakdown, with the same no-purchase messages.

3. `getLikelyPurchaseDay`
- Pulls likely day insights from a distribution result.
- Supports overall year or a specific season.

## Knot data support

Normalization is included to support common Knot-style shapes:
- Top-level arrays or nested arrays in `purchases`, `transactions`, `items`, `data`, or `results`.
- Date keys such as `timestamp`, `purchase_date`, `transaction_time`, `created_at`, etc.
- Amount keys such as `amount`, `total`, `subtotal`, `value`, including nested `{ value }` forms.

## Install and run

```bash
npm install
npm run typecheck
npm run build
```

Example runner:

`src/exampleRunner.ts`

This registers all tools with `DedalusRunner` from `dedalus-labs`.

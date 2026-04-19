import { getSeason, inDateRange, normalizeKnotPurchases } from "./normalize.js";
import { PeriodStats, PurchasePoint, SeasonMap } from "./types.js";

function buildEmptyStats(message: string): PeriodStats {
  return {
    count: 0,
    mean: 0,
    std: 0,
    min: 0,
    max: 0,
    range: 0,
    message,
  };
}

function calcStats(points: PurchasePoint[]): PeriodStats {
  if (!points.length) return buildEmptyStats("no purchases in the period");
  const values = points.map((p) => p.amount);
  const count = values.length;
  const mean = values.reduce((sum, v) => sum + v, 0) / count;
  const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / count;
  const std = Math.sqrt(variance);
  const min = Math.min(...values);
  const max = Math.max(...values);

  return {
    count,
    mean,
    std,
    min,
    max,
    range: max - min,
  };
}

/**
 * Compute purchase amount statistics for a date range.
 * Always returns the overall range stats and seasonal stats (winter/spring/summer/fall).
 * Works with Knot-style input arrays/objects that include purchase timestamps and amounts.
 */
export function computePurchaseStatsByPeriod(
  knotData: unknown,
  date1: string,
  date2: string,
) {
  const normalized = normalizeKnotPurchases(knotData);
  const inRange = normalized.filter((p) => inDateRange(p.timestamp, date1, date2));

  if (!inRange.length) {
    return {
      date1,
      date2,
      message: `no purchases between ${date1}-${date2}`,
      yearTotal: buildEmptyStats("no purchases in the year"),
      bySeason: {
        winter: buildEmptyStats("no purchases in the season"),
        spring: buildEmptyStats("no purchases in the season"),
        summer: buildEmptyStats("no purchases in the season"),
        fall: buildEmptyStats("no purchases in the season"),
      } satisfies SeasonMap<PeriodStats>,
    };
  }

  const seasonalBuckets: Record<"winter" | "spring" | "summer" | "fall", PurchasePoint[]> = {
    winter: [],
    spring: [],
    summer: [],
    fall: [],
  };

  for (const point of inRange) {
    seasonalBuckets[getSeason(point.timestamp)].push(point);
  }

  return {
    date1,
    date2,
    yearTotal: calcStats(inRange),
    bySeason: {
      winter: seasonalBuckets.winter.length
        ? calcStats(seasonalBuckets.winter)
        : buildEmptyStats("no purchases in the season"),
      spring: seasonalBuckets.spring.length
        ? calcStats(seasonalBuckets.spring)
        : buildEmptyStats("no purchases in the season"),
      summer: seasonalBuckets.summer.length
        ? calcStats(seasonalBuckets.summer)
        : buildEmptyStats("no purchases in the season"),
      fall: seasonalBuckets.fall.length
        ? calcStats(seasonalBuckets.fall)
        : buildEmptyStats("no purchases in the season"),
    } satisfies SeasonMap<PeriodStats>,
  };
}

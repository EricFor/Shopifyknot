import { getSeason, inDateRange, normalizeKnotPurchases } from "./normalize.js";
import { PeriodDistribution, PurchasePoint, SeasonMap } from "./types.js";

const DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

function getIsoWeek(date: Date): number {
  const target = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const dayNr = (target.getUTCDay() + 6) % 7;
  target.setUTCDate(target.getUTCDate() - dayNr + 3);
  const firstThursday = new Date(Date.UTC(target.getUTCFullYear(), 0, 4));
  const diff = target.getTime() - firstThursday.getTime();
  return 1 + Math.round(diff / 604800000);
}

function bump(map: Record<string, number>, key: string) {
  map[key] = (map[key] || 0) + 1;
}

function argExtreme(record: Record<string, number>, mode: "max" | "min"): string | null {
  const entries = Object.entries(record);
  if (!entries.length) return null;
  let best = entries[0];
  for (let i = 1; i < entries.length; i += 1) {
    const current = entries[i];
    const better = mode === "max" ? current[1] > best[1] : current[1] < best[1];
    if (better) best = current;
  }
  return best[0];
}

function emptyDistribution(message: string): PeriodDistribution {
  return {
    count: 0,
    byDayOfWeek: {},
    byHourOfDay: {},
    byWeekOfYear: {},
    byMonth: {},
    byDayOfMonth: {},
    mostLikelyDayOfWeek: null,
    leastLikelyDayOfWeek: null,
    message,
  };
}

function buildDistribution(points: PurchasePoint[]): PeriodDistribution {
  if (!points.length) return emptyDistribution("no purchases in the period");

  const byDayOfWeek: Record<string, number> = {};
  const byHourOfDay: Record<string, number> = {};
  const byWeekOfYear: Record<string, number> = {};
  const byMonth: Record<string, number> = {};
  const byDayOfMonth: Record<string, number> = {};

  for (const point of points) {
    const d = new Date(point.timestamp);
    const dayName = DAY_NAMES[d.getUTCDay()];
    bump(byDayOfWeek, dayName);
    bump(byHourOfDay, String(d.getUTCHours()).padStart(2, "0"));
    bump(byWeekOfYear, String(getIsoWeek(d)));
    bump(byMonth, String(d.getUTCMonth() + 1).padStart(2, "0"));
    bump(byDayOfMonth, String(d.getUTCDate()).padStart(2, "0"));
  }

  return {
    count: points.length,
    byDayOfWeek,
    byHourOfDay,
    byWeekOfYear,
    byMonth,
    byDayOfMonth,
    mostLikelyDayOfWeek: argExtreme(byDayOfWeek, "max"),
    leastLikelyDayOfWeek: argExtreme(byDayOfWeek, "min"),
  };
}

/**
 * Compute purchase-time distributions over a date range.
 * Returns year-total and season-level distributions, plus likely/unlikely purchase days.
 * Includes local buckets useful for analysis: day-of-week, hour, week-of-year, month, and day-of-month.
 */
export function computePurchaseTimeDistribution(
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
      yearTotal: emptyDistribution("no purchases in the year"),
      bySeason: {
        winter: emptyDistribution("no purchases in the season"),
        spring: emptyDistribution("no purchases in the season"),
        summer: emptyDistribution("no purchases in the season"),
        fall: emptyDistribution("no purchases in the season"),
      } satisfies SeasonMap<PeriodDistribution>,
    };
  }

  const seasonalBuckets: Record<"winter" | "spring" | "summer" | "fall", PurchasePoint[]> = {
    winter: [],
    spring: [],
    summer: [],
    fall: [],
  };
  for (const point of inRange) seasonalBuckets[getSeason(point.timestamp)].push(point);

  return {
    date1,
    date2,
    yearTotal: buildDistribution(inRange),
    bySeason: {
      winter: seasonalBuckets.winter.length
        ? buildDistribution(seasonalBuckets.winter)
        : emptyDistribution("no purchases in the season"),
      spring: seasonalBuckets.spring.length
        ? buildDistribution(seasonalBuckets.spring)
        : emptyDistribution("no purchases in the season"),
      summer: seasonalBuckets.summer.length
        ? buildDistribution(seasonalBuckets.summer)
        : emptyDistribution("no purchases in the season"),
      fall: seasonalBuckets.fall.length
        ? buildDistribution(seasonalBuckets.fall)
        : emptyDistribution("no purchases in the season"),
    } satisfies SeasonMap<PeriodDistribution>,
  };
}

/**
 * Pull the least/most likely purchase day-of-week from a distribution result.
 * Set season to "yearTotal" for full range, or to a season for focused analysis.
 */
export function getLikelyPurchaseDay(
  distributionResult: ReturnType<typeof computePurchaseTimeDistribution>,
  mode: "mostLikely" | "leastLikely",
  season: "yearTotal" | "winter" | "spring" | "summer" | "fall" = "yearTotal",
) {
  if ("message" in distributionResult && distributionResult.message) {
    return distributionResult.message;
  }

  const target =
    season === "yearTotal" ? distributionResult.yearTotal : distributionResult.bySeason[season];

  if (target.count === 0) return target.message ?? "no purchases in the selected period";
  return mode === "mostLikely" ? target.mostLikelyDayOfWeek : target.leastLikelyDayOfWeek;
}

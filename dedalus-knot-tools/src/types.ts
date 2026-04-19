export type SeasonName = "winter" | "spring" | "summer" | "fall";

export type PurchasePoint = {
  timestamp: string;
  amount: number;
  raw: unknown;
};

export type PeriodStats = {
  count: number;
  mean: number;
  std: number;
  min: number;
  max: number;
  range: number;
  message?: string;
};

export type PeriodDistribution = {
  count: number;
  byDayOfWeek: Record<string, number>;
  byHourOfDay: Record<string, number>;
  byWeekOfYear: Record<string, number>;
  byMonth: Record<string, number>;
  byDayOfMonth: Record<string, number>;
  mostLikelyDayOfWeek: string | null;
  leastLikelyDayOfWeek: string | null;
  message?: string;
};

export type SeasonMap<T> = Record<SeasonName, T>;

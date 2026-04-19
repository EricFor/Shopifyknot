import Dedalus, { DedalusRunner } from "dedalus-labs";
import {
  computePurchaseStatsByPeriod,
  computePurchaseTimeDistribution,
  getLikelyPurchaseDay,
} from "./index.js";

async function main() {
  const client = new Dedalus({
    apiKey: process.env.DEDALUS_API_KEY,
  });

  const runner = new DedalusRunner(client);

  const result = await runner.run({
    input:
      "Use knot purchase data to compute year and seasonal stats, then identify the least likely day of week to buy.",
    model: "openai/gpt-5.2",
    tools: [computePurchaseStatsByPeriod, computePurchaseTimeDistribution, getLikelyPurchaseDay],
  });

  console.log(result.finalOutput);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

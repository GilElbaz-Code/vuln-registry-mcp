import { z } from "zod";
import type { VulnRepository } from "../repository/repository.js";
import { jsonResult } from "./json-result.js";

export const getStatisticsShape = {
  group_by: z
    .enum(["severity", "status", "vendor"])
    .optional()
    .describe("Optionally include a grouped breakdown alongside the headline statistics"),
};

const GetStatisticsInput = z.object(getStatisticsShape);
export type GetStatisticsInput = z.infer<typeof GetStatisticsInput>;

export function getStatistics(repo: VulnRepository, input: GetStatisticsInput) {
  const stats = repo.getStatistics();

  if (!input.group_by) {
    return jsonResult(stats);
  }

  let breakdown: unknown;
  if (input.group_by === "severity") {
    breakdown = stats.by_severity;
  } else if (input.group_by === "status") {
    breakdown = stats.by_status;
  } else {
    breakdown = repo.vendorBreakdown();
  }

  return jsonResult({ ...stats, group_by: input.group_by, breakdown });
}

import { z } from "zod";
import type { VulnRepository } from "../repository/repository.js";
import { jsonResult } from "./json-result.js";

export const searchVulnerabilitiesShape = {
  severity: z
    .array(z.enum(["critical", "high", "medium", "low"]))
    .optional()
    .describe("Only include vulnerabilities with one of these severities"),
  status: z.enum(["open", "patched"]).optional().describe("Only include vulnerabilities with this patch status"),
  vendor_id: z.string().optional().describe("Only include vulnerabilities from this vendor's internal id, e.g. V2"),
  vendor_name: z.string().optional().describe("Case-insensitive substring match against the vendor name"),
  keyword: z.string().optional().describe("Case-insensitive substring match against the title or CVE id"),
  min_cvss: z.number().min(0).max(10).optional().describe("Minimum CVSS score, inclusive"),
  max_cvss: z.number().min(0).max(10).optional().describe("Maximum CVSS score, inclusive"),
  published_after: z.string().optional().describe("Only include vulnerabilities published on/after this date (YYYY-MM-DD)"),
  published_before: z.string().optional().describe("Only include vulnerabilities published on/before this date (YYYY-MM-DD)"),
  limit: z.number().int().positive().max(200).default(50).describe("Maximum number of results to return"),
};

const SearchVulnerabilitiesInput = z.object(searchVulnerabilitiesShape);
export type SearchVulnerabilitiesInput = z.infer<typeof SearchVulnerabilitiesInput>;

export function searchVulnerabilities(repo: VulnRepository, input: SearchVulnerabilitiesInput) {
  const { limit, ...filters } = input;
  const matched = repo.search(filters);
  const results = matched.slice(0, limit);
  return jsonResult({ count: results.length, total_matched: matched.length, results });
}

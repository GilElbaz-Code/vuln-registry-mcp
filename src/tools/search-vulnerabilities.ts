import { z } from "zod";
import type { VulnRepository } from "../repository/repository.js";
import { jsonResult } from "./json-result.js";

// Publish dates are compared lexicographically, which is only correct for
// zero-padded ISO dates — reject anything else at the schema boundary.
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export const searchVulnerabilitiesShape = {
  severity: z
    .array(z.enum(["critical", "high", "medium", "low"]))
    .min(1, "provide at least one severity, or omit the filter entirely")
    .optional()
    .describe("Only include vulnerabilities with one of these severities"),
  status: z.enum(["open", "patched"]).optional().describe("Only include vulnerabilities with this patch status"),
  vendor_id: z.string().optional().describe("Only include vulnerabilities from this vendor's internal id, e.g. V2"),
  vendor_name: z.string().optional().describe("Case-insensitive substring match against the vendor name"),
  keyword: z.string().optional().describe("Case-insensitive substring match against the title or CVE id"),
  min_cvss: z.number().min(0).max(10).optional().describe("Minimum CVSS score, inclusive"),
  max_cvss: z.number().min(0).max(10).optional().describe("Maximum CVSS score, inclusive"),
  published_after: z
    .string()
    .regex(ISO_DATE, "must be a zero-padded YYYY-MM-DD date")
    .optional()
    .describe("Only include vulnerabilities published on/after this date (YYYY-MM-DD)"),
  published_before: z
    .string()
    .regex(ISO_DATE, "must be a zero-padded YYYY-MM-DD date")
    .optional()
    .describe("Only include vulnerabilities published on/before this date (YYYY-MM-DD)"),
  limit: z.number().int().positive().max(200).default(50).describe("Maximum number of results to return per page"),
  offset: z
    .number()
    .int()
    .min(0)
    .default(0)
    .describe("Number of matched results to skip before the page starts (pagination)"),
};

const SearchVulnerabilitiesInput = z.object(searchVulnerabilitiesShape);
export type SearchVulnerabilitiesInput = z.infer<typeof SearchVulnerabilitiesInput>;

export function searchVulnerabilities(repo: VulnRepository, input: SearchVulnerabilitiesInput) {
  const { limit, offset, ...filters } = input;
  const matched = repo.search(filters);
  const results = matched.slice(offset, offset + limit);
  return jsonResult({
    count: results.length,
    total_matched: matched.length,
    offset,
    has_more: offset + results.length < matched.length,
    results,
  });
}

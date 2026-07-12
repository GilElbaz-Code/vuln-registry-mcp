import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VulnRepository } from "../repository/repository.js";
import { getStatistics, getStatisticsShape } from "./get-statistics.js";
import { getVendorProfile, getVendorProfileShape } from "./get-vendor-profile.js";
import { getVulnerability, getVulnerabilityShape } from "./get-vulnerability.js";
import { listVendors, listVendorsShape } from "./list-vendors.js";
import { searchVulnerabilities, searchVulnerabilitiesShape } from "./search-vulnerabilities.js";

export function registerTools(server: McpServer, getRepo: () => VulnRepository): void {
  server.registerTool(
    "search_vulnerabilities",
    {
      title: "Search vulnerabilities",
      description:
        "Search the vulnerability registry with combinable filters (severity, status, vendor, CVSS range, " +
        "publish date range, keyword). All filters are optional and combine with AND; an empty call returns " +
        "everything up to the limit. Results are sorted by CVSS score (desc), then publish date (desc); " +
        "page through large result sets with limit and offset.",
      inputSchema: searchVulnerabilitiesShape,
    },
    async (input) => searchVulnerabilities(getRepo(), input),
  );

  server.registerTool(
    "get_vulnerability",
    {
      title: "Get a single vulnerability",
      description:
        "Look up one vulnerability by CVE id, internal id, or title. Resolves through a strict-to-fuzzy " +
        "ladder: exact id, exact CVE id (prefix/case-insensitive), exact title, then partial title match. " +
        "If the identifier is ambiguous or not found, returns candidates/suggestions instead of guessing.",
      inputSchema: getVulnerabilityShape,
    },
    async (input) => getVulnerability(getRepo(), input),
  );

  server.registerTool(
    "list_vendors",
    {
      title: "List vendors",
      description: "List all registered vendors with their vulnerability count, open count, and severity breakdown.",
      inputSchema: listVendorsShape,
    },
    async (input) => listVendors(getRepo(), input),
  );

  server.registerTool(
    "get_vendor_profile",
    {
      title: "Get a vendor profile",
      description:
        "Look up one vendor by internal id or name (exact or partial) and return its details plus every " +
        "vulnerability attributed to it with summary statistics (open/patched counts, severity breakdown, " +
        "average and max CVSS). Ambiguous or unmatched names return candidates/suggestions instead of guessing.",
      inputSchema: getVendorProfileShape,
    },
    async (input) => getVendorProfile(getRepo(), input),
  );

  server.registerTool(
    "get_statistics",
    {
      title: "Get registry-wide statistics",
      description:
        "Get headline statistics for the whole registry: totals, severity/status breakdowns, open critical " +
        "count, average and highest CVSS score, publish date range, vendor count, and orphaned-vendor-id " +
        "count. Optionally add a grouped breakdown by severity, status, or vendor.",
      inputSchema: getStatisticsShape,
    },
    async (input) => getStatistics(getRepo(), input),
  );
}

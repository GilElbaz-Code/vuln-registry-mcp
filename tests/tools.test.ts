import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { describe, expect, it } from "vitest";
import { parseDbFile } from "../src/parser/parser.js";
import { VulnRepository } from "../src/repository/repository.js";
import { getStatistics, getStatisticsShape } from "../src/tools/get-statistics.js";
import { getVendorProfile, getVendorProfileShape } from "../src/tools/get-vendor-profile.js";
import { getVulnerability, getVulnerabilityShape } from "../src/tools/get-vulnerability.js";
import { listVendors, listVendorsShape } from "../src/tools/list-vendors.js";
import { searchVulnerabilities, searchVulnerabilitiesShape } from "../src/tools/search-vulnerabilities.js";

const dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(dirname, "..", "data");

function buildRealRepo(): VulnRepository {
  const vendorsFile = parseDbFile(fs.readFileSync(path.join(dataDir, "vendors.db"), "utf-8"), "vendors.db");
  const vulnsFile = parseDbFile(
    fs.readFileSync(path.join(dataDir, "vulnerabilities.db"), "utf-8"),
    "vulnerabilities.db",
  );
  return VulnRepository.fromParsed(vendorsFile, vulnsFile);
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): unknown {
  const first = result.content[0];
  if (!first || typeof first.text !== "string") throw new Error("expected a text content block");
  return JSON.parse(first.text);
}

const repo = buildRealRepo();

describe("Zod input validation", () => {
  it("rejects an out-of-range cvss value for search_vulnerabilities", () => {
    const schema = z.object(searchVulnerabilitiesShape);
    const result = schema.safeParse({ min_cvss: 11 });
    expect(result.success).toBe(false);
  });

  it("rejects a bad severity enum value for search_vulnerabilities", () => {
    const schema = z.object(searchVulnerabilitiesShape);
    const result = schema.safeParse({ severity: ["catastrophic"] });
    expect(result.success).toBe(false);
  });

  it("rejects an empty identifier for get_vulnerability", () => {
    const schema = z.object(getVulnerabilityShape);
    expect(schema.safeParse({ identifier: "" }).success).toBe(false);
    expect(schema.safeParse({ identifier: "CVE001" }).success).toBe(true);
  });

  it("applies the default limit for search_vulnerabilities when omitted", () => {
    const schema = z.object(searchVulnerabilitiesShape);
    const result = schema.parse({});
    expect(result.limit).toBe(50);
  });
});

describe("get_vulnerability resolution ladder", () => {
  it("resolves by exact internal id", () => {
    const result = textOf(getVulnerability(repo, { identifier: "CVE001" })) as {
      found: boolean;
      matched_by: string;
      vulnerability: { title: string };
    };
    expect(result.found).toBe(true);
    expect(result.matched_by).toBe("id");
    expect(result.vulnerability.title).toBe("Log4Shell");
  });

  it("resolves by CVE id in prefixed, unprefixed, and lowercase forms", () => {
    for (const identifier of ["CVE-2021-44228", "cve-2021-44228", "2021-44228"]) {
      const result = textOf(getVulnerability(repo, { identifier })) as {
        found: boolean;
        matched_by: string;
        vulnerability: { id: string };
      };
      expect(result.found, `identifier "${identifier}"`).toBe(true);
      expect(result.matched_by).toBe("cve_id");
      expect(result.vulnerability.id).toBe("CVE001");
    }
  });

  it("resolves by exact title, case-insensitively", () => {
    const result = textOf(getVulnerability(repo, { identifier: "log4shell" })) as {
      found: boolean;
      matched_by: string;
    };
    expect(result.found).toBe(true);
    expect(result.matched_by).toBe("title");
  });

  it("resolves a single partial title match and flags it as such", () => {
    const result = textOf(getVulnerability(repo, { identifier: "eternal" })) as {
      found: boolean;
      matched_by: string;
      vulnerability: { title: string };
    };
    expect(result.found).toBe(true);
    expect(result.matched_by).toBe("partial_title");
    expect(result.vulnerability.title).toBe("EternalBlue");
  });

  it("returns disambiguation candidates instead of guessing when multiple titles match", () => {
    const result = textOf(getVulnerability(repo, { identifier: "dirty" })) as {
      found: boolean;
      ambiguous: boolean;
      candidates: Array<{ title: string }>;
    };
    expect(result.found).toBe(false);
    expect(result.ambiguous).toBe(true);
    expect(result.candidates.map((c) => c.title).sort()).toEqual(["Dirty COW", "Dirty Pipe"]);
  });

  it("does not conflate similarly named but distinct vulnerabilities on a partial query", () => {
    // "PrintNightmare" alone is an exact title (CVE008) and resolves directly — the ladder
    // only needs to disambiguate when the query itself doesn't exactly name one of them.
    const result = textOf(getVulnerability(repo, { identifier: "print" })) as {
      found: boolean;
      ambiguous: boolean;
      candidates: Array<{ title: string }>;
    };
    expect(result.found).toBe(false);
    expect(result.ambiguous).toBe(true);
    expect(result.candidates.map((c) => c.title).sort()).toEqual(["PrintNightmare", "PrintNightmare RCE"]);
  });

  it("returns suggestions and a hint when nothing matches", () => {
    const result = textOf(getVulnerability(repo, { identifier: "totally-unknown-thing" })) as {
      found: boolean;
      ambiguous: boolean;
      suggestions: unknown[];
      hint: string;
    };
    expect(result.found).toBe(false);
    expect(result.ambiguous).toBe(false);
    expect(result.hint).toMatch(/search_vulnerabilities/);
  });
});

describe("search_vulnerabilities tool", () => {
  it("returns everything within the default limit when called with no filters", () => {
    const result = textOf(searchVulnerabilities(repo, { limit: 50 })) as {
      count: number;
      total_matched: number;
    };
    expect(result.total_matched).toBe(20);
    expect(result.count).toBe(20);
  });

  it("combines severity and status filters", () => {
    const result = textOf(
      searchVulnerabilities(repo, { severity: ["critical"], status: "open", limit: 50 }),
    ) as { results: Array<{ id: string }> };
    expect(result.results.map((r) => r.id).sort()).toEqual(["CVE019", "CVE020"]);
  });

  it("respects the limit and reports total_matched separately from count", () => {
    const result = textOf(searchVulnerabilities(repo, { severity: ["high"], limit: 2 })) as {
      count: number;
      total_matched: number;
    };
    expect(result.total_matched).toBe(10);
    expect(result.count).toBe(2);
  });

  it("sorts results by cvss_score desc", () => {
    const result = textOf(searchVulnerabilities(repo, { limit: 200 })) as {
      results: Array<{ cvss_score: number }>;
    };
    const scores = result.results.map((r) => r.cvss_score);
    const sorted = [...scores].sort((a, b) => b - a);
    expect(scores).toEqual(sorted);
  });
});

describe("list_vendors tool", () => {
  it("lists all vendors with vuln counts, sorted by vuln_count desc by default", () => {
    const result = textOf(listVendors(repo, { sort_by: "vuln_count" })) as {
      count: number;
      vendors: Array<{ id: string; vuln_count: number }>;
    };
    expect(result.count).toBe(5);
    const counts = result.vendors.map((v) => v.vuln_count);
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
  });

  it("sorts alphabetically by name when requested", () => {
    const result = textOf(listVendors(repo, { sort_by: "name" })) as {
      vendors: Array<{ name: string }>;
    };
    const names = result.vendors.map((v) => v.name);
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
  });
});

describe("get_vendor_profile tool", () => {
  it("resolves by exact id", () => {
    const result = textOf(getVendorProfile(repo, { identifier: "V2" })) as {
      found: boolean;
      matched_by: string;
      name: string;
      stats: { total: number };
    };
    expect(result.found).toBe(true);
    expect(result.matched_by).toBe("id");
    expect(result.name).toBe("Apache Software Foundation");
    expect(result.stats.total).toBeGreaterThan(0);
  });

  it("resolves by partial name", () => {
    const result = textOf(getVendorProfile(repo, { identifier: "apache" })) as {
      found: boolean;
      matched_by: string;
      id: string;
    };
    expect(result.found).toBe(true);
    expect(result.id).toBe("V2");
  });

  it("returns not-found suggestions for an unknown vendor", () => {
    const result = textOf(getVendorProfile(repo, { identifier: "NoSuchVendorXYZ" })) as {
      found: boolean;
      hint: string;
    };
    expect(result.found).toBe(false);
    expect(result.hint).toMatch(/list_vendors/);
  });
});

describe("get_statistics tool", () => {
  it("returns headline statistics with no group_by", () => {
    const result = textOf(getStatistics(repo, {})) as { total_vulnerabilities: number; group_by?: string };
    expect(result.total_vulnerabilities).toBe(20);
    expect(result.group_by).toBeUndefined();
  });

  it("adds a vendor breakdown when group_by is 'vendor'", () => {
    const result = textOf(getStatistics(repo, { group_by: "vendor" })) as {
      breakdown: Array<{ vendor_id: string; count: number }>;
    };
    const total = result.breakdown.reduce((sum, b) => sum + b.count, 0);
    expect(total).toBe(20);
  });
});

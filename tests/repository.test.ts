import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseDbFile } from "../src/parser/parser.js";
import { VulnRepository } from "../src/repository/repository.js";

const dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(dirname, "..", "data");

const VENDORS = `# FORMAT: type|id|name|category|hq|founded
# VERSION: 1.0

VENDOR|V1|Microsoft|Software|Redmond, WA|1975
VENDOR|V2|Apache Software Foundation|Open Source|Wilmington, DE|1999
`;

const VULNS = `# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published
# VERSION: 1.0

VULN|CVE001|CVE-2021-44228|Log4Shell|V2|critical|10.0|2.0-2.14.1|patched|2021-12-10
VULN|CVE002|CVE-2017-0144|EternalBlue|V1|critical|9.8|Windows 7-2008 R2|patched|2017-03-14
VULN|CVE003|CVE-2014-3566|POODLE|V2|medium|3.4|SSLv3|patched|2014-10-14
VULN|CVE004|CVE-2023-9999|Orphan Vuln|V9|high|5.0|Whatever|open|2023-01-01
`;

function buildRepo(vendorsText: string, vulnsText: string): VulnRepository {
  const vendorsFile = parseDbFile(vendorsText, "vendors.db");
  const vulnsFile = parseDbFile(vulnsText, "vulnerabilities.db");
  return VulnRepository.fromParsed(vendorsFile, vulnsFile);
}

describe("VulnRepository — indexing and lookups", () => {
  const repo = buildRepo(VENDORS, VULNS);

  it("looks up vendors and vulnerabilities by id, case-insensitively", () => {
    expect(repo.getVendorById("v1")?.name).toBe("Microsoft");
    expect(repo.getVulnById("cve001")?.title).toBe("Log4Shell");
  });

  it("looks up vulnerabilities by normalized cve_id", () => {
    expect(repo.getVulnByCveId("CVE-2021-44228")?.id).toBe("CVE001");
    expect(repo.getVulnByCveId("cve-2021-44228")?.id).toBe("CVE001");
  });

  it("looks up vulnerabilities by exact normalized title", () => {
    expect(repo.getVulnByTitle("log4shell")?.id).toBe("CVE001");
    expect(repo.getVulnByTitle("LOG4SHELL")?.id).toBe("CVE001");
  });

  it("groups vulnerabilities by vendor_id", () => {
    const vendorId = repo.getVendorById("V2")?.id;
    expect(vendorId).toBe("V2");
  });

  it("finds vulnerabilities by substring title match", () => {
    const matches = repo.findVulnsByTitleContaining("shell");
    expect(matches.map((v) => v.id).sort()).toEqual(["CVE001"]);
  });
});

describe("VulnRepository — vendor join and orphan handling", () => {
  const repo = buildRepo(VENDORS, VULNS);

  it("enriches a vulnerability with its vendor", () => {
    const vuln = repo.getVulnById("CVE001");
    expect(vuln).toBeDefined();
    const enriched = repo.enrich(vuln!);
    expect(enriched.vendor?.name).toBe("Apache Software Foundation");
  });

  it("keeps a record with an orphan vendor_id (vendor: null) instead of dropping it, and counts it", () => {
    const vuln = repo.getVulnById("CVE004");
    expect(vuln).toBeDefined();
    expect(vuln?.vendor_id).toBe("V9");
    const enriched = repo.enrich(vuln!);
    expect(enriched.vendor).toBeNull();
    expect(repo.getOrphanCount()).toBe(1);
  });
});

describe("VulnRepository — duplicate ids and missing vendor_id", () => {
  it("keeps the first occurrence of a duplicate vulnerability id and skips the rest", () => {
    const dupVulns = `# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published
# VERSION: 1.0

VULN|CVE001|CVE-2021-44228|Log4Shell|V2|critical|10.0|2.0-2.14.1|patched|2021-12-10
VULN|CVE001|CVE-2099-0001|Impostor|V1|low|1.0|n/a|open|2099-01-01
`;
    const repo = buildRepo(VENDORS, dupVulns);
    expect(repo.getVulnById("CVE001")?.title).toBe("Log4Shell");
    expect(repo.getAllVulnerabilities()).toHaveLength(1);
  });

  it("keeps the first occurrence of a duplicate vendor id and skips the rest", () => {
    const dupVendors = `# FORMAT: type|id|name|category|hq|founded
# VERSION: 1.0

VENDOR|V1|Microsoft|Software|Redmond, WA|1975
VENDOR|V1|Impostor Corp|Software|Nowhere|2000
`;
    const repo = buildRepo(dupVendors, VULNS);
    expect(repo.getVendorById("V1")?.name).toBe("Microsoft");
    expect(repo.getAllVendors()).toHaveLength(1);
  });

  it("counts an empty vendor_id as an orphan and keeps the record", () => {
    const noVendorVulns = `# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published
# VERSION: 1.0

VULN|CVE001|CVE-2020-0001|Vendorless||high|5.0|n/a|open|2020-01-01
`;
    const repo = buildRepo(VENDORS, noVendorVulns);
    const vuln = repo.getVulnById("CVE001");
    expect(vuln).toBeDefined();
    expect(repo.enrich(vuln!).vendor).toBeNull();
    expect(repo.getOrphanCount()).toBe(1);
  });
});

describe("VulnRepository — vendor breakdown", () => {
  it("includes known vendors (even zero-count) plus a null-named bucket per orphan vendor_id, summing to the total", () => {
    const repo = buildRepo(VENDORS, VULNS);
    const breakdown = repo.vendorBreakdown();

    const total = breakdown.reduce((sum, b) => sum + b.count, 0);
    expect(total).toBe(repo.getAllVulnerabilities().length);

    const orphanBucket = breakdown.find((b) => b.vendor_id === "V9");
    expect(orphanBucket).toEqual({ vendor_id: "V9", vendor_name: null, count: 1 });
  });
});

describe("VulnRepository — coercion and free-text fields", () => {
  it("coerces cvss_score and founded to numbers", () => {
    const repo = buildRepo(VENDORS, VULNS);
    expect(repo.getVulnById("CVE001")?.cvss_score).toBe(10.0);
    expect(repo.getVendorById("V1")?.founded).toBe(1975);
  });

  it("skips a vulnerability row with a non-numeric cvss_score, keeping the rest", () => {
    const badVulns = `# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published
# VERSION: 1.0

VULN|CVE001|CVE-2021-44228|Log4Shell|V2|critical|not-a-number|2.0-2.14.1|patched|2021-12-10
VULN|CVE002|CVE-2017-0144|EternalBlue|V1|critical|9.8|Windows 7-2008 R2|patched|2017-03-14
`;
    const repo = buildRepo(VENDORS, badVulns);
    expect(repo.getVulnById("CVE001")).toBeUndefined();
    expect(repo.getVulnById("CVE002")).toBeDefined();
  });

  it("keeps affected_versions as untouched free text", () => {
    const repo = buildRepo(VENDORS, VULNS);
    expect(repo.getVulnById("CVE002")?.affected_versions).toBe("Windows 7-2008 R2");
  });

  it("normalizes severity/status casing at load so filters and breakdowns stay consistent", () => {
    const mixedCase = `# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published
# VERSION: 1.0

VULN|CVE001|CVE-2020-0001|Shouty Row|V1|CRITICAL|9.0|n/a|Open|2020-01-01
`;
    const repo = buildRepo(VENDORS, mixedCase);
    expect(repo.getVulnById("CVE001")?.severity).toBe("critical");
    expect(repo.getVulnById("CVE001")?.status).toBe("open");
    expect(repo.search({ severity: ["critical"], status: "open" })).toHaveLength(1);
    expect(repo.getStatistics().by_severity["critical"]).toBe(1);
  });
});

describe("VulnRepository — search filters", () => {
  const repo = buildRepo(VENDORS, VULNS);

  it("returns everything (minus orphan exclusions from other filters) when no filters are given", () => {
    expect(repo.search({})).toHaveLength(4);
  });

  it("combines severity and status filters", () => {
    const results = repo.search({ severity: ["critical"], status: "patched" });
    expect(results.map((v) => v.id).sort()).toEqual(["CVE001", "CVE002"]);
  });

  it("filters by cvss range", () => {
    const results = repo.search({ min_cvss: 5, max_cvss: 9.9 });
    expect(results.map((v) => v.id).sort()).toEqual(["CVE002", "CVE004"]);
  });

  it("filters by published date range", () => {
    const results = repo.search({ published_after: "2015-01-01", published_before: "2020-01-01" });
    expect(results.map((v) => v.id)).toEqual(["CVE002"]);
  });

  it("filters by keyword across title and cve_id", () => {
    expect(repo.search({ keyword: "log4" }).map((v) => v.id)).toEqual(["CVE001"]);
    expect(repo.search({ keyword: "2017-0144" }).map((v) => v.id)).toEqual(["CVE002"]);
  });

  it("filters by vendor_name substring, case-insensitively", () => {
    const results = repo.search({ vendor_name: "apache" });
    expect(results.map((v) => v.id).sort()).toEqual(["CVE001", "CVE003"]);
  });

  it("sorts results by cvss_score desc, then published desc", () => {
    const results = repo.search({});
    expect(results.map((v) => v.id)).toEqual(["CVE001", "CVE002", "CVE004", "CVE003"]);
  });
});

describe("VulnRepository — list_vendors and vendor profile", () => {
  const repo = buildRepo(VENDORS, VULNS);

  it("lists vendors with vuln counts and severity breakdown", () => {
    const vendors = repo.listVendors();
    const apache = vendors.find((v) => v.id === "V2");
    expect(apache?.vuln_count).toBe(2);
    expect(apache?.severity_breakdown["critical"]).toBe(1);
    expect(apache?.severity_breakdown["medium"]).toBe(1);
    expect(apache?.open_count).toBe(0);
  });

  it("builds a vendor profile with stats and enriched vulnerabilities", () => {
    const profile = repo.getVendorProfile("V2");
    expect(profile).not.toBeNull();
    expect(profile?.stats.total).toBe(2);
    expect(profile?.stats.patched).toBe(2);
    expect(profile?.stats.max_cvss).toBe(10.0);
    expect(profile?.vulnerabilities.map((v) => v.id)).toEqual(["CVE001", "CVE003"]);
  });

  it("returns null for an unknown vendor id", () => {
    expect(repo.getVendorProfile("V999")).toBeNull();
  });
});

describe("VulnRepository — statistics against the real dataset", () => {
  const vendorsText = fs.readFileSync(path.join(dataDir, "vendors.db"), "utf-8");
  const vulnsText = fs.readFileSync(path.join(dataDir, "vulnerabilities.db"), "utf-8");
  const repo = buildRepo(vendorsText, vulnsText);

  it("computes headline statistics matching the known 20-row dataset", () => {
    const stats = repo.getStatistics();

    expect(stats.total_vulnerabilities).toBe(20);
    expect(stats.vendor_count).toBe(5);
    expect(stats.orphan_count).toBe(0);
    expect(stats.by_severity["critical"]).toBe(9);
    expect(stats.by_severity["high"]).toBe(10);
    expect(stats.by_severity["medium"]).toBe(1);
    expect(stats.by_status["open"]).toBe(4);
    expect(stats.by_status["patched"]).toBe(16);
    expect(stats.open_critical_count).toBe(2);
    expect(stats.avg_cvss).toBeCloseTo(8.44, 2);
    expect(stats.highest?.id).toBe("CVE001");
    expect(stats.highest?.cvss_score).toBe(10.0);
    expect(stats.published_date_range).toEqual({ earliest: "2014-04-07", latest: "2024-03-04" });
  });
});

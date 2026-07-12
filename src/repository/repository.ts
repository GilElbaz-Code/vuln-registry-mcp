import { logger } from "../logger.js";
import type { ParsedFile } from "../parser/types.js";
import type {
  EnrichedVulnerability,
  SeverityBreakdown,
  Statistics,
  Vendor,
  VendorProfile,
  VendorWithCounts,
  VulnQuery,
  Vulnerability,
} from "./types.js";

const KNOWN_SEVERITIES = ["critical", "high", "medium", "low"];

function emptySeverityBreakdown(): SeverityBreakdown {
  const breakdown: SeverityBreakdown = {};
  for (const s of KNOWN_SEVERITIES) breakdown[s] = 0;
  return breakdown;
}

function addToBreakdown(breakdown: SeverityBreakdown, severity: string): void {
  const key = severity.toLowerCase();
  breakdown[key] = (breakdown[key] ?? 0) + 1;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * Holds the parsed registry in memory and answers queries via prebuilt Maps
 * (id, cve_id, title, vendor_id) rather than repeated array scans. All
 * domain knowledge — column meaning, coercion, the vendor join — lives here;
 * the parser upstream is schema-agnostic.
 */
export class VulnRepository {
  private readonly vendorsById = new Map<string, Vendor>();
  private readonly vulnsById = new Map<string, Vulnerability>();
  private readonly vulnsByCveId = new Map<string, Vulnerability>();
  private readonly vulnsByNormalizedTitle = new Map<string, Vulnerability>();
  private readonly vulnsByVendorId = new Map<string, Vulnerability[]>();
  private readonly allVulnsList: Vulnerability[] = [];
  private orphanCount = 0;

  private constructor() {}

  static fromParsed(vendorsFile: ParsedFile, vulnerabilitiesFile: ParsedFile): VulnRepository {
    const repo = new VulnRepository();

    for (const warning of vendorsFile.warnings) logger.warn(warning.message);
    for (const warning of vulnerabilitiesFile.warnings) logger.warn(warning.message);

    vendorsFile.rows.forEach((row, i) => {
      const line = vendorsFile.rowLines[i];
      const rawId = row["id"];
      if (!rawId) {
        logger.warn(`${vendorsFile.sourceName}:${line}: skipped vendor row with missing id`);
        return;
      }

      const rawFounded = row["founded"];
      const founded = Number(rawFounded);
      if (rawFounded === undefined || Number.isNaN(founded)) {
        logger.warn(
          `${vendorsFile.sourceName}:${line}: skipped vendor row ${rawId} — non-numeric founded value "${rawFounded}"`,
        );
        return;
      }

      const vendor: Vendor = {
        id: rawId.toUpperCase(),
        name: row["name"] ?? "",
        category: row["category"] ?? "",
        hq: row["hq"] ?? "",
        founded,
      };
      repo.vendorsById.set(vendor.id, vendor);
    });

    vulnerabilitiesFile.rows.forEach((row, i) => {
      const line = vulnerabilitiesFile.rowLines[i];
      const rawId = row["id"];
      if (!rawId) {
        logger.warn(`${vulnerabilitiesFile.sourceName}:${line}: skipped vulnerability row with missing id`);
        return;
      }

      const rawCvss = row["cvss_score"];
      const cvssScore = Number(rawCvss);
      if (rawCvss === undefined || Number.isNaN(cvssScore)) {
        logger.warn(
          `${vulnerabilitiesFile.sourceName}:${line}: skipped vulnerability row ${rawId} — non-numeric cvss_score "${rawCvss}"`,
        );
        return;
      }

      const vendorId = (row["vendor_id"] ?? "").toUpperCase();
      if (vendorId && !repo.vendorsById.has(vendorId)) {
        logger.warn(
          `${vulnerabilitiesFile.sourceName}:${line}: orphan vendor_id "${vendorId}" on ${rawId} — keeping record`,
        );
        repo.orphanCount++;
      }

      const vuln: Vulnerability = {
        id: rawId.toUpperCase(),
        cve_id: (row["cve_id"] ?? "").toUpperCase(),
        title: row["title"] ?? "",
        vendor_id: vendorId,
        severity: row["severity"] ?? "",
        cvss_score: cvssScore,
        affected_versions: row["affected_versions"] ?? "",
        status: row["status"] ?? "",
        published: row["published"] ?? "",
      };

      repo.vulnsById.set(vuln.id, vuln);
      if (vuln.cve_id) repo.vulnsByCveId.set(vuln.cve_id, vuln);
      if (vuln.title) repo.vulnsByNormalizedTitle.set(vuln.title.toLowerCase(), vuln);

      const vendorList = repo.vulnsByVendorId.get(vuln.vendor_id) ?? [];
      vendorList.push(vuln);
      repo.vulnsByVendorId.set(vuln.vendor_id, vendorList);

      repo.allVulnsList.push(vuln);
    });

    return repo;
  }

  getVendorById(id: string): Vendor | undefined {
    return this.vendorsById.get(id.toUpperCase());
  }

  getAllVendors(): Vendor[] {
    return Array.from(this.vendorsById.values());
  }

  findVendorsByNameContaining(substring: string): Vendor[] {
    const needle = substring.toLowerCase();
    return this.getAllVendors().filter((v) => v.name.toLowerCase().includes(needle));
  }

  getVulnById(id: string): Vulnerability | undefined {
    return this.vulnsById.get(id.toUpperCase());
  }

  getVulnByCveId(normalizedCveId: string): Vulnerability | undefined {
    return this.vulnsByCveId.get(normalizedCveId.toUpperCase());
  }

  getVulnByTitle(title: string): Vulnerability | undefined {
    return this.vulnsByNormalizedTitle.get(title.toLowerCase());
  }

  findVulnsByTitleContaining(substring: string): Vulnerability[] {
    const needle = substring.toLowerCase();
    return this.allVulnsList.filter((v) => v.title.toLowerCase().includes(needle));
  }

  getAllVulnerabilities(): Vulnerability[] {
    return this.allVulnsList;
  }

  getOrphanCount(): number {
    return this.orphanCount;
  }

  enrich(vuln: Vulnerability): EnrichedVulnerability {
    return { ...vuln, vendor: this.vendorsById.get(vuln.vendor_id) ?? null };
  }

  search(query: VulnQuery): EnrichedVulnerability[] {
    const severitySet = query.severity ? new Set(query.severity.map((s) => s.toLowerCase())) : null;
    const keyword = query.keyword?.toLowerCase();
    const vendorName = query.vendor_name?.toLowerCase();
    const vendorId = query.vendor_id?.toUpperCase();

    const results = this.allVulnsList.map((v) => this.enrich(v)).filter((v) => {
      if (severitySet && !severitySet.has(v.severity.toLowerCase())) return false;
      if (query.status && v.status.toLowerCase() !== query.status.toLowerCase()) return false;
      if (vendorId && v.vendor_id !== vendorId) return false;
      if (vendorName && !(v.vendor?.name.toLowerCase().includes(vendorName) ?? false)) return false;
      if (keyword) {
        const haystack = `${v.title} ${v.cve_id}`.toLowerCase();
        if (!haystack.includes(keyword)) return false;
      }
      if (query.min_cvss !== undefined && v.cvss_score < query.min_cvss) return false;
      if (query.max_cvss !== undefined && v.cvss_score > query.max_cvss) return false;
      if (query.published_after && v.published < query.published_after) return false;
      if (query.published_before && v.published > query.published_before) return false;
      return true;
    });

    results.sort((a, b) => {
      if (b.cvss_score !== a.cvss_score) return b.cvss_score - a.cvss_score;
      return b.published.localeCompare(a.published);
    });

    return results;
  }

  listVendors(sortBy: "vuln_count" | "name" = "vuln_count"): VendorWithCounts[] {
    const list: VendorWithCounts[] = this.getAllVendors().map((vendor) => {
      const vulns = this.vulnsByVendorId.get(vendor.id) ?? [];
      const breakdown = emptySeverityBreakdown();
      let openCount = 0;
      for (const v of vulns) {
        addToBreakdown(breakdown, v.severity);
        if (v.status.toLowerCase() === "open") openCount++;
      }
      return { ...vendor, vuln_count: vulns.length, open_count: openCount, severity_breakdown: breakdown };
    });

    if (sortBy === "name") {
      list.sort((a, b) => a.name.localeCompare(b.name));
    } else {
      list.sort((a, b) => b.vuln_count - a.vuln_count || a.name.localeCompare(b.name));
    }
    return list;
  }

  getVendorProfile(vendorId: string): VendorProfile | null {
    const vendor = this.getVendorById(vendorId);
    if (!vendor) return null;

    const vulns = (this.vulnsByVendorId.get(vendor.id) ?? []).map((v) => this.enrich(v));
    const bySeverity = emptySeverityBreakdown();
    let open = 0;
    let patched = 0;
    let cvssSum = 0;
    let maxCvss = 0;
    for (const v of vulns) {
      addToBreakdown(bySeverity, v.severity);
      if (v.status.toLowerCase() === "open") open++;
      else patched++;
      cvssSum += v.cvss_score;
      if (v.cvss_score > maxCvss) maxCvss = v.cvss_score;
    }

    const sortedVulns = [...vulns].sort((a, b) => {
      if (b.cvss_score !== a.cvss_score) return b.cvss_score - a.cvss_score;
      return b.published.localeCompare(a.published);
    });

    return {
      ...vendor,
      stats: {
        total: vulns.length,
        open,
        patched,
        by_severity: bySeverity,
        avg_cvss: vulns.length ? round2(cvssSum / vulns.length) : 0,
        max_cvss: maxCvss,
      },
      vulnerabilities: sortedVulns,
    };
  }

  getStatistics(): Statistics {
    const bySeverity = emptySeverityBreakdown();
    const byStatus: Record<string, number> = {};
    let cvssSum = 0;
    let highest: EnrichedVulnerability | null = null;
    let earliest: string | null = null;
    let latest: string | null = null;
    let openCritical = 0;

    for (const v of this.allVulnsList) {
      addToBreakdown(bySeverity, v.severity);
      const statusKey = v.status.toLowerCase();
      byStatus[statusKey] = (byStatus[statusKey] ?? 0) + 1;
      cvssSum += v.cvss_score;
      if (v.severity.toLowerCase() === "critical" && statusKey === "open") openCritical++;

      if (!highest || v.cvss_score > highest.cvss_score) highest = this.enrich(v);

      if (v.published) {
        if (earliest === null || v.published < earliest) earliest = v.published;
        if (latest === null || v.published > latest) latest = v.published;
      }
    }

    return {
      total_vulnerabilities: this.allVulnsList.length,
      by_severity: bySeverity,
      by_status: byStatus,
      open_critical_count: openCritical,
      avg_cvss: this.allVulnsList.length ? round2(cvssSum / this.allVulnsList.length) : 0,
      highest,
      published_date_range: { earliest, latest },
      vendor_count: this.vendorsById.size,
      orphan_count: this.orphanCount,
    };
  }
}

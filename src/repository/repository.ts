import { logger } from "../logger.js";
import type { ParsedFile } from "../parser/types.js";
import type {
  EnrichedVulnerability,
  SeverityBreakdown,
  Statistics,
  StatisticsByVendor,
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
  breakdown[severity] = (breakdown[severity] ?? 0) + 1;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** The canonical result ordering: CVSS score descending, then publish date descending. */
function byCvssThenPublishedDesc(a: Vulnerability, b: Vulnerability): number {
  return b.cvss_score - a.cvss_score || b.published.localeCompare(a.published);
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
  /** Lowercased titles aligned with allVulnsList, so text scans never re-lowercase per query. */
  private readonly lowerTitles: string[] = [];
  private orphanCount = 0;
  // The dataset is immutable after load, so derived aggregates are computed once and cached.
  private cachedStatistics: Statistics | null = null;
  private cachedVendorCounts: VendorWithCounts[] | null = null;

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
      if (repo.vendorsById.has(vendor.id)) {
        logger.warn(
          `${vendorsFile.sourceName}:${line}: skipped duplicate vendor id ${vendor.id} — keeping the first occurrence`,
        );
        return;
      }
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

      if (repo.vulnsById.has(rawId.toUpperCase())) {
        logger.warn(
          `${vulnerabilitiesFile.sourceName}:${line}: skipped duplicate vulnerability id ${rawId.toUpperCase()} — keeping the first occurrence`,
        );
        return;
      }

      const vendorId = (row["vendor_id"] ?? "").toUpperCase();
      if (!repo.vendorsById.has(vendorId)) {
        logger.warn(
          vendorId
            ? `${vulnerabilitiesFile.sourceName}:${line}: orphan vendor_id "${vendorId}" on ${rawId} — keeping record`
            : `${vulnerabilitiesFile.sourceName}:${line}: missing vendor_id on ${rawId} — keeping record`,
        );
        repo.orphanCount++;
      }

      const vuln: Vulnerability = {
        id: rawId.toUpperCase(),
        cve_id: (row["cve_id"] ?? "").toUpperCase(),
        title: row["title"] ?? "",
        vendor_id: vendorId,
        // Enum-ish fields are normalized once at load so every query and
        // breakdown compares directly instead of re-lowercasing per row.
        severity: (row["severity"] ?? "").toLowerCase(),
        cvss_score: cvssScore,
        affected_versions: row["affected_versions"] ?? "",
        status: (row["status"] ?? "").toLowerCase(),
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

    // Sort once at load into the canonical order; search() and profiles then
    // return pre-ordered slices instead of re-sorting on every query.
    repo.allVulnsList.sort(byCvssThenPublishedDesc);
    for (const list of repo.vulnsByVendorId.values()) list.sort(byCvssThenPublishedDesc);
    for (const v of repo.allVulnsList) repo.lowerTitles.push(v.title.toLowerCase());

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
    const matches: Vulnerability[] = [];
    for (let i = 0; i < this.allVulnsList.length; i++) {
      if (this.lowerTitles[i]!.includes(needle)) matches.push(this.allVulnsList[i]!);
    }
    return matches;
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
    // Normalize all query terms once, outside the scan loop. Row-side fields
    // (severity, status, cve_id) are already normalized at load.
    const severitySet = query.severity ? new Set(query.severity.map((s) => s.toLowerCase())) : null;
    const status = query.status?.toLowerCase();
    const keywordLower = query.keyword?.toLowerCase();
    const keywordUpper = query.keyword?.toUpperCase();
    const vendorName = query.vendor_name?.toLowerCase();
    const vendorId = query.vendor_id?.toUpperCase();

    // Start from the vendor index when the query pins a vendor; filter before
    // enriching so non-matching rows never allocate an enriched copy. Cheap
    // checks (set/equality/numeric) run before substring scans.
    const pool = vendorId !== undefined ? this.vulnsByVendorId.get(vendorId) ?? [] : this.allVulnsList;
    const poolIsFullList = pool === this.allVulnsList;

    const results: EnrichedVulnerability[] = [];
    for (let i = 0; i < pool.length; i++) {
      const v = pool[i]!;
      if (severitySet && !severitySet.has(v.severity)) continue;
      if (status !== undefined && v.status !== status) continue;
      if (query.min_cvss !== undefined && v.cvss_score < query.min_cvss) continue;
      if (query.max_cvss !== undefined && v.cvss_score > query.max_cvss) continue;
      if (query.published_after && v.published < query.published_after) continue;
      if (query.published_before && v.published > query.published_before) continue;
      if (vendorName !== undefined) {
        const vendor = this.vendorsById.get(v.vendor_id);
        if (!vendor || !vendor.name.toLowerCase().includes(vendorName)) continue;
      }
      if (keywordLower !== undefined) {
        const titleLower = poolIsFullList ? this.lowerTitles[i]! : v.title.toLowerCase();
        if (!titleLower.includes(keywordLower) && !v.cve_id.includes(keywordUpper!)) continue;
      }
      results.push(this.enrich(v));
    }

    // Already in canonical order: the source lists are sorted once at load.
    return results;
  }

  listVendors(sortBy: "vuln_count" | "name" = "vuln_count"): VendorWithCounts[] {
    if (this.cachedVendorCounts === null) {
      this.cachedVendorCounts = this.getAllVendors().map((vendor) => {
        const vulns = this.vulnsByVendorId.get(vendor.id) ?? [];
        const breakdown = emptySeverityBreakdown();
        let openCount = 0;
        for (const v of vulns) {
          addToBreakdown(breakdown, v.severity);
          if (v.status === "open") openCount++;
        }
        return { ...vendor, vuln_count: vulns.length, open_count: openCount, severity_breakdown: breakdown };
      });
    }
    const list = [...this.cachedVendorCounts];

    if (sortBy === "name") {
      list.sort((a, b) => a.name.localeCompare(b.name));
    } else {
      list.sort((a, b) => b.vuln_count - a.vuln_count || a.name.localeCompare(b.name));
    }
    return list;
  }

  /**
   * Per-vendor vulnerability counts covering every record: known vendors
   * (including zero-count ones) plus a `vendor_name: null` bucket for each
   * orphaned/missing vendor_id, so the counts always sum to the total.
   */
  vendorBreakdown(): StatisticsByVendor[] {
    const breakdown: StatisticsByVendor[] = this.getAllVendors().map((vendor) => ({
      vendor_id: vendor.id,
      vendor_name: vendor.name,
      count: (this.vulnsByVendorId.get(vendor.id) ?? []).length,
    }));
    for (const [vendorId, vulns] of this.vulnsByVendorId) {
      if (!this.vendorsById.has(vendorId)) {
        breakdown.push({ vendor_id: vendorId, vendor_name: null, count: vulns.length });
      }
    }
    breakdown.sort((a, b) => b.count - a.count || a.vendor_id.localeCompare(b.vendor_id));
    return breakdown;
  }

  getVendorProfile(vendorId: string): VendorProfile | null {
    const vendor = this.getVendorById(vendorId);
    if (!vendor) return null;
    return this.buildVendorProfile(vendor);
  }

  /** Builds a profile for an already-resolved Vendor — always succeeds, since the vendor is known to exist. */
  buildVendorProfile(vendor: Vendor): VendorProfile {
    const vulns = (this.vulnsByVendorId.get(vendor.id) ?? []).map((v) => this.enrich(v));
    const bySeverity = emptySeverityBreakdown();
    let open = 0;
    let patched = 0;
    let cvssSum = 0;
    let maxCvss = 0;
    for (const v of vulns) {
      addToBreakdown(bySeverity, v.severity);
      if (v.status === "open") open++;
      else patched++;
      cvssSum += v.cvss_score;
      if (v.cvss_score > maxCvss) maxCvss = v.cvss_score;
    }

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
      // Already in canonical order: per-vendor lists are sorted once at load.
      vulnerabilities: vulns,
    };
  }

  getStatistics(): Statistics {
    if (this.cachedStatistics === null) this.cachedStatistics = this.computeStatistics();
    return this.cachedStatistics;
  }

  private computeStatistics(): Statistics {
    const bySeverity = emptySeverityBreakdown();
    const byStatus: Record<string, number> = {};
    let cvssSum = 0;
    let earliest: string | null = null;
    let latest: string | null = null;
    let openCritical = 0;

    for (const v of this.allVulnsList) {
      addToBreakdown(bySeverity, v.severity);
      byStatus[v.status] = (byStatus[v.status] ?? 0) + 1;
      cvssSum += v.cvss_score;
      if (v.severity === "critical" && v.status === "open") openCritical++;

      if (v.published) {
        if (earliest === null || v.published < earliest) earliest = v.published;
        if (latest === null || v.published > latest) latest = v.published;
      }
    }

    // The list is sorted by CVSS descending at load, so the top scorer is index 0.
    const first = this.allVulnsList[0];
    const highest = first ? this.enrich(first) : null;

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

export interface Vendor {
  id: string;
  name: string;
  category: string;
  hq: string;
  founded: number;
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  vendor_id: string;
  severity: string;
  cvss_score: number;
  affected_versions: string;
  status: string;
  published: string;
}

export interface EnrichedVulnerability extends Vulnerability {
  vendor: Vendor | null;
}

/** Counts keyed by severity string; always includes the known CVSS bands, plus any others seen in the data. */
export type SeverityBreakdown = Record<string, number>;

export interface VulnQuery {
  severity?: string[];
  status?: string;
  vendor_id?: string;
  vendor_name?: string;
  keyword?: string;
  min_cvss?: number;
  max_cvss?: number;
  published_after?: string;
  published_before?: string;
}

export interface VendorWithCounts extends Vendor {
  vuln_count: number;
  open_count: number;
  severity_breakdown: SeverityBreakdown;
}

export interface VendorProfile extends Vendor {
  stats: {
    total: number;
    open: number;
    patched: number;
    by_severity: SeverityBreakdown;
    avg_cvss: number;
    max_cvss: number;
  };
  vulnerabilities: EnrichedVulnerability[];
}

export interface Statistics {
  total_vulnerabilities: number;
  by_severity: SeverityBreakdown;
  by_status: Record<string, number>;
  open_critical_count: number;
  avg_cvss: number;
  highest: EnrichedVulnerability | null;
  published_date_range: { earliest: string | null; latest: string | null };
  vendor_count: number;
  orphan_count: number;
}

export interface StatisticsByVendor {
  vendor_id: string;
  vendor_name: string | null;
  count: number;
}

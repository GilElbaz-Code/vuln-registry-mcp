/**
 * Synthetic-scale benchmark: generates a dataset ~5000x the sample size
 * (1,000 vendors / 100,000 vulnerabilities), then times load and the query
 * paths each tool uses. Run with: npm run bench
 *
 * This is a standalone script, not the MCP server — stdout is fine here.
 */
import { performance } from "node:perf_hooks";
import { parseDbFile } from "../src/parser/parser.js";
import { VulnRepository } from "../src/repository/repository.js";

const VENDOR_COUNT = 1_000;
const VULN_COUNT = 100_000;

const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = ["open", "patched"];

function buildVendorsText(): string {
  const lines = ["# FORMAT: type|id|name|category|hq|founded", "# VERSION: 1.0", ""];
  for (let i = 1; i <= VENDOR_COUNT; i++) {
    lines.push(`VENDOR|V${i}|Vendor ${i} Corp|Software|City ${i % 100}|${1970 + (i % 50)}`);
  }
  return lines.join("\n");
}

function buildVulnsText(): string {
  const lines = [
    "# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published",
    "# VERSION: 1.0",
    "",
  ];
  for (let i = 1; i <= VULN_COUNT; i++) {
    const year = 2014 + (i % 11);
    const month = String((i % 12) + 1).padStart(2, "0");
    const day = String((i % 28) + 1).padStart(2, "0");
    lines.push(
      [
        "VULN",
        `CVE${String(i).padStart(6, "0")}`,
        `CVE-${year}-${10_000 + i}`,
        `Synthetic ${i % 7 === 0 ? "Kernel" : "Component"} Flaw ${i}`,
        `V${(i % VENDOR_COUNT) + 1}`,
        SEVERITIES[i % SEVERITIES.length],
        ((i % 100) / 10).toFixed(1),
        `1.0-${i % 20}.${i % 10}`,
        STATUSES[i % STATUSES.length],
        `${year}-${month}-${day}`,
      ].join("|"),
    );
  }
  return lines.join("\n");
}

function time<T>(label: string, fn: () => T): T {
  const start = performance.now();
  const out = fn();
  console.log(`${label.padEnd(58)} ${(performance.now() - start).toFixed(1).padStart(8)} ms`);
  return out;
}

console.log(`dataset: ${VENDOR_COUNT.toLocaleString()} vendors, ${VULN_COUNT.toLocaleString()} vulnerabilities\n`);

const vendorsText = buildVendorsText();
const vulnsText = buildVulnsText();

const vendorsFile = time("parse vendors.db", () => parseDbFile(vendorsText, "vendors.db"));
const vulnsFile = time("parse vulnerabilities.db", () => parseDbFile(vulnsText, "vulnerabilities.db"));
const repo = time("build repository (indexes + load-time sort)", () =>
  VulnRepository.fromParsed(vendorsFile, vulnsFile),
);

console.log("");
time("search: severity=critical + status=open (full scan)", () =>
  repo.search({ severity: ["critical"], status: "open" }),
);
time("search: keyword 'kernel' (full scan)", () => repo.search({ keyword: "kernel" }));
time("search: vendor_id=V500 (index-seeded)", () => repo.search({ vendor_id: "V500" }));
time("get_statistics (first call, computed)", () => repo.getStatistics());
time("get_statistics (cached)", () => repo.getStatistics());
time("list_vendors (first call, computed)", () => repo.listVendors());
time("list_vendors (cached)", () => repo.listVendors());
time("10,000 point lookups by cve_id (Map)", () => {
  for (let i = 1; i <= 10_000; i++) repo.getVulnByCveId(`CVE-${2014 + (i % 11)}-${10_000 + i}`);
});

const heapMb = process.memoryUsage().heapUsed / 1024 / 1024;
console.log(`\nheap used after load: ${heapMb.toFixed(0)} MB`);

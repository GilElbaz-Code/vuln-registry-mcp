import { describe, expect, it } from "vitest";
import { parseDbFile } from "../src/parser/parser.js";
import { Registry } from "../src/registry.js";
import { VulnRepository } from "../src/repository/repository.js";

const VENDORS = `# FORMAT: type|id|name|category|hq|founded
# VERSION: 1.0

VENDOR|V1|Microsoft|Software|Redmond, WA|1975
`;

function repoWithVulns(vulnRows: string): VulnRepository {
  const vulns = `# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published
# VERSION: 1.0

${vulnRows}`;
  return VulnRepository.fromParsed(parseDbFile(VENDORS, "vendors.db"), parseDbFile(vulns, "vulnerabilities.db"));
}

describe("Registry hot reload", () => {
  it("serves the new repository after a successful reload", () => {
    const initial = repoWithVulns("VULN|CVE001|CVE-2021-44228|Log4Shell|V1|critical|10.0|2.x|patched|2021-12-10\n");
    const next = repoWithVulns(
      "VULN|CVE001|CVE-2021-44228|Log4Shell|V1|critical|10.0|2.x|patched|2021-12-10\n" +
        "VULN|CVE002|CVE-2017-0144|EternalBlue|V1|critical|9.8|Win7|patched|2017-03-14\n",
    );

    const registry = new Registry(initial);
    expect(registry.repo.getAllVulnerabilities()).toHaveLength(1);

    expect(registry.reload(() => next)).toBe(true);
    expect(registry.repo).toBe(next);
    expect(registry.repo.getAllVulnerabilities()).toHaveLength(2);
  });

  it("keeps serving the last-good repository when a reload fails", () => {
    const initial = repoWithVulns("VULN|CVE001|CVE-2021-44228|Log4Shell|V1|critical|10.0|2.x|patched|2021-12-10\n");
    const registry = new Registry(initial);

    expect(
      registry.reload(() => {
        throw new Error("data file is corrupt mid-write");
      }),
    ).toBe(false);
    expect(registry.repo).toBe(initial);
    expect(registry.repo.getAllVulnerabilities()).toHaveLength(1);
  });
});

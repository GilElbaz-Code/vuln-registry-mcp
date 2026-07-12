import fs from "node:fs";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { parseDbFile } from "./parser/parser.js";
import { VulnRepository } from "./repository/repository.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  let vendorsText: string;
  let vulnerabilitiesText: string;
  try {
    vendorsText = fs.readFileSync(config.vendorsFile, "utf-8");
    vulnerabilitiesText = fs.readFileSync(config.vulnerabilitiesFile, "utf-8");
  } catch (err) {
    logger.error(`failed to read data files: ${(err as Error).message}`);
    process.exit(1);
  }

  let repo: VulnRepository;
  try {
    const vendorsFile = parseDbFile(vendorsText, config.vendorsFile);
    const vulnerabilitiesFile = parseDbFile(vulnerabilitiesText, config.vulnerabilitiesFile);
    repo = VulnRepository.fromParsed(vendorsFile, vulnerabilitiesFile);
  } catch (err) {
    logger.error(`failed to parse data files: ${(err as Error).message}`);
    process.exit(1);
  }

  logger.info(
    `loaded ${repo.getAllVendors().length} vendors and ${repo.getAllVulnerabilities().length} vulnerabilities ` +
      `(${repo.getOrphanCount()} orphaned vendor_id reference(s))`,
  );

  const server = createServer(repo);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("vuln-registry-mcp server connected over stdio");
}

main().catch((err) => {
  logger.error(`fatal startup error: ${(err as Error).message}`);
  process.exit(1);
});

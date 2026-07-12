import fs from "node:fs";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { parseDbFile } from "./parser/parser.js";
import { VulnRepository } from "./repository/repository.js";

/** Reads and parses both data files from disk into a fresh repository. */
export function loadRepository(): VulnRepository {
  const vendorsText = fs.readFileSync(config.vendorsFile, "utf-8");
  const vulnerabilitiesText = fs.readFileSync(config.vulnerabilitiesFile, "utf-8");
  const vendorsFile = parseDbFile(vendorsText, config.vendorsFile);
  const vulnerabilitiesFile = parseDbFile(vulnerabilitiesText, config.vulnerabilitiesFile);
  return VulnRepository.fromParsed(vendorsFile, vulnerabilitiesFile);
}

/**
 * Holds the currently-served repository and swaps it atomically on reload.
 * A failed reload (unreadable/corrupt files) keeps the last-good repository
 * in place, so a bad write to the data files never takes the server down.
 */
export class Registry {
  private current: VulnRepository;

  constructor(initial: VulnRepository) {
    this.current = initial;
  }

  get repo(): VulnRepository {
    return this.current;
  }

  reload(load: () => VulnRepository = loadRepository): boolean {
    try {
      const next = load();
      this.current = next;
      logger.info(
        `reloaded registry: ${next.getAllVendors().length} vendors, ` +
          `${next.getAllVulnerabilities().length} vulnerabilities ` +
          `(${next.getOrphanCount()} orphaned vendor_id reference(s))`,
      );
      return true;
    } catch (err) {
      logger.error(`reload failed — keeping last-good data: ${(err as Error).message}`);
      return false;
    }
  }
}

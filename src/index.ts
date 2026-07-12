import fs from "node:fs";
import path from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { loadRepository, Registry } from "./registry.js";
import { createServer } from "./server.js";

const RELOAD_DEBOUNCE_MS = 300;

/**
 * Watches the data directory and hot-reloads the registry when either data
 * file changes, debounced so a burst of write events triggers one reload.
 * Failure to watch is non-fatal — the server just requires a restart to pick
 * up data changes. Disable with VULN_WATCH=0.
 */
function watchDataFiles(registry: Registry): fs.FSWatcher | null {
  if (process.env["VULN_WATCH"] === "0") return null;

  const watchedNames = new Set([path.basename(config.vendorsFile), path.basename(config.vulnerabilitiesFile)]);
  let timer: NodeJS.Timeout | null = null;

  try {
    const watcher = fs.watch(config.dataDir, (_event, filename) => {
      if (filename && !watchedNames.has(filename)) return;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => registry.reload(), RELOAD_DEBOUNCE_MS);
      timer.unref();
    });
    // The watcher must not keep the process alive once the stdio transport closes.
    watcher.unref();
    logger.info(`watching ${config.dataDir} for data file changes (set VULN_WATCH=0 to disable)`);
    return watcher;
  } catch (err) {
    logger.warn(`file watching unavailable — restart the server to pick up data changes (${(err as Error).message})`);
    return null;
  }
}

async function main(): Promise<void> {
  let registry: Registry;
  try {
    registry = new Registry(loadRepository());
  } catch (err) {
    logger.error(`failed to load data files: ${(err as Error).message}`);
    process.exit(1);
  }

  logger.info(
    `loaded ${registry.repo.getAllVendors().length} vendors and ` +
      `${registry.repo.getAllVulnerabilities().length} vulnerabilities ` +
      `(${registry.repo.getOrphanCount()} orphaned vendor_id reference(s))`,
  );

  const watcher = watchDataFiles(registry);
  const server = createServer(registry);
  const transport = new StdioServerTransport();

  const shutdown = (signal: string): void => {
    logger.info(`received ${signal} — shutting down`);
    watcher?.close();
    void server.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  await server.connect(transport);
  logger.info("vuln-registry-mcp server connected over stdio");
}

main().catch((err) => {
  logger.error(`fatal startup error: ${(err as Error).message}`);
  process.exit(1);
});

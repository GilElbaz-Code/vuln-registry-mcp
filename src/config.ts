import path from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(moduleDir, "..");

const dataDir = process.env["VULN_DATA_DIR"] ?? path.join(projectRoot, "data");

export const config = {
  dataDir,
  vendorsFile: path.join(dataDir, "vendors.db"),
  vulnerabilitiesFile: path.join(dataDir, "vulnerabilities.db"),
};

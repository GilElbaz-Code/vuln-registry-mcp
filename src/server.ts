import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Registry } from "./registry.js";
import { registerTools } from "./tools/index.js";

export function createServer(registry: Registry): McpServer {
  const server = new McpServer({
    name: "vuln-registry-mcp",
    version: "0.1.0",
  });

  // Tools resolve the repository per call, so a hot reload takes effect
  // without re-registering anything.
  registerTools(server, () => registry.repo);

  return server;
}

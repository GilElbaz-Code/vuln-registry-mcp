import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VulnRepository } from "./repository/repository.js";
import { registerTools } from "./tools/index.js";

export function createServer(repo: VulnRepository): McpServer {
  const server = new McpServer({
    name: "vuln-registry-mcp",
    version: "0.1.0",
  });

  registerTools(server, repo);

  return server;
}

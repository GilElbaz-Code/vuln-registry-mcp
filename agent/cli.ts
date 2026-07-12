import readline from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import { GoogleGenAI } from "@google/genai";
import type { Content, FunctionDeclaration } from "@google/genai";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const MODEL = process.env["GEMINI_MODEL"] ?? "gemini-flash-latest";
const MAX_TOOL_ROUNDS = 8;

function trace(message: string): void {
  process.stderr.write(`[agent] ${message}\n`);
}

async function connectToServer(): Promise<Client> {
  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const serverEntry = path.resolve(moduleDir, "..", "dist", "index.js");

  if (!fs.existsSync(serverEntry)) {
    trace(`server build not found at ${serverEntry}`);
    trace(`run "npm run build" first, then retry.`);
    process.exit(1);
  }

  const client = new Client({ name: "vuln-registry-agent", version: "0.1.0" });
  const transport = new StdioClientTransport({ command: "node", args: [serverEntry] });
  await client.connect(transport);
  return client;
}

async function buildFunctionDeclarations(client: Client): Promise<FunctionDeclaration[]> {
  const { tools } = await client.listTools();
  return tools.map((tool) => ({
    name: tool.name,
    description: tool.description ?? "",
    parametersJsonSchema: tool.inputSchema,
  }));
}

function extractToolResultText(result: Awaited<ReturnType<Client["callTool"]>>): unknown {
  const content = result.content;
  if (!Array.isArray(content) || content.length === 0) return result;
  const first = content[0] as { type?: string; text?: string };
  if (first.type === "text" && typeof first.text === "string") {
    try {
      return JSON.parse(first.text);
    } catch {
      return first.text;
    }
  }
  return result;
}

async function ask(ai: GoogleGenAI, client: Client, declarations: FunctionDeclaration[], question: string): Promise<string> {
  const contents: Content[] = [{ role: "user", parts: [{ text: question }] }];

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const response = await ai.models.generateContent({
      model: MODEL,
      contents,
      config: { tools: [{ functionDeclarations: declarations }] },
    });

    const functionCalls = response.functionCalls;
    if (!functionCalls || functionCalls.length === 0) {
      return response.text ?? "(no response text)";
    }

    const modelContent = response.candidates?.[0]?.content ?? {
      role: "model",
      parts: functionCalls.map((fc) => ({ functionCall: fc })),
    };
    contents.push(modelContent);

    const responseParts = [];
    for (const call of functionCalls) {
      const name = call.name ?? "";
      trace(`calling tool ${name}(${JSON.stringify(call.args ?? {})})`);
      const result = await client.callTool({ name, arguments: call.args ?? {} });
      const output = extractToolResultText(result);
      responseParts.push({ functionResponse: { id: call.id, name, response: { output } } });
    }
    contents.push({ role: "user", parts: responseParts });
  }

  return "(stopped after too many tool-call rounds without a final answer)";
}

async function main(): Promise<void> {
  const apiKey = process.env["GEMINI_API_KEY"];
  if (!apiKey) {
    trace('GEMINI_API_KEY is not set. The MCP server and Claude Desktop still work without it;');
    trace("set GEMINI_API_KEY to use this CLI agent.");
    process.exit(1);
  }

  const client = await connectToServer();
  try {
    const declarations = await buildFunctionDeclarations(client);
    trace(`connected — ${declarations.length} tools available: ${declarations.map((d) => d.name).join(", ")}`);

    const ai = new GoogleGenAI({ apiKey });

    const positionalQuestion = process.argv.slice(2).join(" ").trim();
    if (positionalQuestion) {
      const answer = await ask(ai, client, declarations, positionalQuestion);
      console.log(answer);
      return;
    }

    trace('interactive mode — type a question and press enter (Ctrl+D or "exit" to quit)');
    await runInteractive(ai, client, declarations);
  } finally {
    // Always close the subprocess transport before the process exits — exiting while
    // its stdio pipes are still open crashes libuv on Windows (UV_HANDLE_CLOSING assert).
    await client.close();
  }
}

function runInteractive(ai: GoogleGenAI, client: Client, declarations: FunctionDeclaration[]): Promise<void> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: "> " });
    rl.prompt();
    rl.on("line", (line) => {
      const question = line.trim();
      if (!question) {
        rl.prompt();
        return;
      }
      if (question === "exit" || question === "quit") {
        rl.close();
        return;
      }
      ask(ai, client, declarations, question)
        .then((answer) => {
          console.log(answer);
          rl.prompt();
        })
        .catch((err) => {
          trace(`error: ${(err as Error).message}`);
          rl.prompt();
        });
    });
    rl.on("close", () => resolve());
  });
}

main().catch((err) => {
  trace(`fatal error: ${(err as Error).message}`);
  process.exitCode = 1;
});

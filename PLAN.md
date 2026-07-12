# Vulnerability Registry MCP Server — Implementation Plan

## Context

Deloitte take-home (`docs/ASSIGNMENT.md`): a legacy client keeps its CVE database in
plain-text, pipe-delimited files (`data/vendors.db`, `data/vulnerabilities.db`) with no
API. We wrap those files in an **MCP server** so any MCP client (Claude Desktop, a custom
agent) can query them in natural language. Phase 2 adds an optional CLI agent.

The data files are text despite the `.db` extension. Confirmed shapes:

- `vendors.db` — `# FORMAT: type|id|name|category|hq|founded`, `# VERSION: 1.0`, 5 rows (`VENDOR|V1|Microsoft|...`).
- `vulnerabilities.db` — `# FORMAT: type|id|cve_id|title|vendor_id|severity|cvss_score|affected_versions|status|published`, `# VERSION: 1.0`, 20 rows (`VULN|CVE001|CVE-2021-44228|Log4Shell|V2|critical|10.0|2.0-2.14.1|patched|2021-12-10`).
- Observed `severity` ∈ {critical, high, medium}; `status` ∈ {open, patched}. `vendor_id` → vendor `id`.

**Goal of this doc:** a concrete build plan honoring every hard rule in `CLAUDE.md`
(schema-agnostic parser, stderr-only logging, free-text `affected_versions`, skip-don't-crash,
orphan validation, Map-based indexing).

---

## 1. Project structure

```
vuln-registry-mcp/
├── data/                       # existing .db files (unchanged)
├── docs/ASSIGNMENT.md          # existing
├── src/
│   ├── index.ts                # entry: build repo from files, start stdio server
│   ├── server.ts               # createServer(repo): McpServer + tool registration
│   ├── logger.ts               # stderr-only logger (info/warn/error)
│   ├── config.ts               # resolve data file paths (env override + defaults)
│   ├── parser/
│   │   ├── parser.ts           # schema-agnostic pipe parser
│   │   └── types.ts            # ParsedFile, ParsedRow, ParseWarning
│   ├── repository/
│   │   ├── repository.ts       # VulnRepository: mapping, indexes, joins, queries
│   │   └── types.ts            # Vendor, Vulnerability, EnrichedVulnerability, filter/stat types
│   └── tools/
│       ├── index.ts            # registerTools(server, repo)
│       ├── search-vulnerabilities.ts
│       ├── get-vulnerability.ts
│       ├── list-vendors.ts
│       ├── get-vendor-profile.ts
│       └── get-statistics.ts
├── agent/
│   └── cli.ts                  # Phase 2: Gemini CLI agent (spawns server as MCP subprocess)
├── tests/
│   ├── parser.test.ts
│   ├── repository.test.ts
│   ├── tools.test.ts
│   └── fixtures/               # tiny .db samples: malformed row, orphan vendor_id, bad VERSION
├── package.json                # scripts: test, build, dev, agent
├── tsconfig.json               # strict, NodeNext, target ES2022, outDir dist
├── vitest.config.ts
├── README.md
└── PLAN.md
```

Dependencies: `@modelcontextprotocol/sdk`, `zod` (runtime); `typescript`, `vitest`, `tsx`,
`@types/node` (dev). Phase 2 adds **`@google/genai`** (approved) — used only by `agent/cli.ts`.

---

## 2. Schema-agnostic parser (`src/parser/`)

The parser knows nothing about vendors vs. vulnerabilities. It turns a `.db` file into named
rows using the `# FORMAT` header — **never hardcoded indices**.

**`parseDbFile(text, sourceName): ParsedFile`**

1. Split into lines; track 1-based line numbers for warnings.
2. Metadata: lines starting with `#`.
   - `# FORMAT: a|b|c` → `columns: string[]` (split on `|`, trim). Required; if absent → throw a
     clear startup error (can't map without it).
   - `# VERSION: x` → `version: string`. Compare against `SUPPORTED_VERSIONS = ["1.0"]`. Unknown
     version → **stderr warn, keep parsing** (per hard rule).
3. Data rows: non-empty, non-`#` lines. Split on `|`, trim each field.
   - Field count ≠ `columns.length` → **skip row, stderr warn with line number**, continue.
   - Zip `columns` → values into `Record<string,string>`; push to `rows`.
4. Return `{ sourceName, version, columns, rows, warnings }`.

Types (`parser/types.ts`): `ParsedRow = Record<string,string>`;
`ParsedFile = { sourceName; version; columns: string[]; rows: ParsedRow[]; warnings: ParseWarning[] }`;
`ParseWarning = { line: number; message: string }`.

Design point for README: the parser is a generic tabular reader; **all domain knowledge
(which columns mean what, type coercion, joins) lives in the repository.** Adding a v1.1 column
requires zero parser changes.

---

## 3. Repository layer (`src/repository/`)

`VulnRepository` maps generic `ParsedRow`s to typed domain objects, builds indexes, validates
the vendor join, and exposes query methods the tools call.

**Domain types** (`repository/types.ts`):

```ts
type Vendor = { id; name; category; hq; founded: number };
type Vulnerability = {
  id; cve_id; title; vendor_id; severity; status;
  cvss_score: number; affected_versions: string;  // free text — NOT parsed
  published: string;                                // ISO date string, kept as-is
};
type EnrichedVulnerability = Vulnerability & { vendor: Vendor | null };
```

**Construction** `VulnRepository.fromParsed(vendorsFile, vulnsFile)`:

- Map rows by column name (e.g. `row["cvss_score"]`), never by position.
- Coercion: `founded`/`cvss_score` → `Number`; if `NaN` on a required numeric → skip row +
  stderr warn (malformed). `affected_versions`/`published` stay strings.
- Build indexes (Maps — no repeated `array.filter`):
  - `vendorsById: Map<string, Vendor>`
  - `vulnsById: Map<string, Vulnerability>` (internal `CVE001`)
  - `vulnsByCveId: Map<string, Vulnerability>` (normalized key, see §4.2)
  - `vulnsByNormalizedTitle: Map<string, Vulnerability>` (lowercased title)
  - `vulnsByVendorId: Map<string, Vulnerability[]>`
- **Orphan validation (startup):** for each vuln, if `vendor_id` ∉ `vendorsById` → stderr warn
  (`orphan vendor_id 'Vx' on CVE...`), **keep the record** (hard rule). Enrichment yields
  `vendor: null` for orphans.

**Query methods** (pure, no logging):

- `search(filters: VulnFilters): EnrichedVulnerability[]`
- `resolveVulnerability(identifier): ResolutionResult` (ladder in §4.2)
- `listVendors(): VendorWithCounts[]`
- `getVendorProfile(id): VendorProfile | null`
- `getStatistics(): Statistics`

Enrichment joins each vuln to its vendor via `vendorsById.get(vendor_id)`.

---

## 4. MCP tools (`src/tools/`)

Registered with `server.registerTool(name, { title, description, inputSchema }, handler)`.
`inputSchema` is a Zod raw shape (the SDK derives JSON Schema). Handlers return
`{ content: [{ type: "text", text: JSON.stringify(result, null, 2) }] }` — structured JSON as
text so the LLM gets clean, parseable output. Not-found / ambiguous are **normal successful
results** with explanatory fields, never thrown errors.

### 4.1 `search_vulnerabilities` — combinable AND filters

```ts
{
  severity: z.array(z.enum(["critical","high","medium","low"])).optional(),
  status:   z.enum(["open","patched"]).optional(),
  vendor_id:   z.string().optional(),
  vendor_name: z.string().optional(),          // case-insensitive substring
  keyword:     z.string().optional(),          // matches title OR cve_id, ci substring
  min_cvss: z.number().min(0).max(10).optional(),
  max_cvss: z.number().min(0).max(10).optional(),
  published_after:  z.string().optional(),     // YYYY-MM-DD, lexicographic compare (ISO)
  published_before: z.string().optional(),
  limit: z.number().int().positive().max(200).default(50),
}
```

All optional → empty filter returns everything (capped by `limit`). Returns
`{ count, total_matched, results: EnrichedVulnerability[] }`. Sorted by `cvss_score` desc then
`published` desc for stable, useful ordering.

### 4.2 `get_vulnerability` — strict→fuzzy resolution ladder

Input: `{ identifier: z.string().min(1) }`. Resolution stops at first hit (logic lives in the
**tool layer** — intent interpretation, not data access):

1. **Exact internal id** — `CVE001`, case-insensitive → `vulnsById`.
2. **Exact cve_id (normalized)** — regex `/^(CVE-)?(\d{4}-\d{4,})$/i`; canonicalize to
   `CVE-YYYY-NNNN` uppercase before lookup, so `cve-2021-44228`, `CVE-2021-44228`, and
   `2021-44228` all resolve → `vulnsByCveId`.
3. **Exact title** — case-insensitive → `vulnsByNormalizedTitle` (`log4shell` → Log4Shell).
4. **Substring title match** — scan titles for the query as substring (only fuzzy step scans):
   - **exactly one** → return it with `"matched_by": "partial_title"` so the LLM knows it was
     fuzzy-resolved.
   - **multiple** → `{ found: false, ambiguous: true, candidates: [{id, cve_id, title}, ...] }`
     — never auto-pick (avoids "PrintNightmare" silently returning "PrintNightmare RCE").
   - **zero** → `{ found: false, suggestions: [...] }` via simple token-overlap scoring over
     titles, plus hint: `"No match for 'X'. Similar entries: … For broader queries use search_vulnerabilities."`

Steps 1–3 are O(1) off prebuilt Maps; only step 4 scans (consistent with the no-filter-scan rule).

### 4.3 `list_vendors` — vendors with vuln counts

Input: `{ sort_by: z.enum(["vuln_count","name"]).default("vuln_count") }`. Returns each vendor
plus `vuln_count`, `open_count`, and `severity_breakdown` ({critical,high,medium,low}), computed
from `vulnsByVendorId` (no scans).

### 4.4 `get_vendor_profile` — one vendor + its vulns + stats

Input: `{ identifier: z.string().min(1) }` (vendor id `V1`, case-insensitive, or name substring;
ambiguous name → candidate list, mirroring §4.2's philosophy). Returns vendor fields +
`stats { total, open, patched, by_severity, avg_cvss, max_cvss }` + full `vulnerabilities` list.
Not found → `{ found: false, suggestions }`.

### 4.5 `get_statistics` — registry-wide overview

Input: `{ group_by: z.enum(["severity","status","vendor"]).optional() }`. Always returns headline
figures: `total_vulnerabilities`, `by_severity`, `by_status`, `open_critical_count`, `avg_cvss`,
`highest` (the top-CVSS vuln), `published_date_range {earliest,latest}`, `vendor_count`,
`orphan_count`. When `group_by` set, adds a grouped breakdown.

---

## 5. Error handling & logging

- **`logger.ts`** — `info/warn/error` all write to `process.stderr` only. No `console.log`
  anywhere (stdout is the JSON-RPC channel — hard rule). One-line lint/grep check in CI note.
- **Parser/repo** — warn + skip on malformed rows and unknown VERSION; never throw on bad data.
  Only genuinely unrecoverable startup problems throw: missing file, missing `# FORMAT` line.
- **Startup** — `index.ts` loads files, logs a summary to stderr (counts, warnings, orphans),
  then connects the stdio transport. If load throws → log to stderr, `process.exit(1)` (can't
  serve without data).
- **Tools** — invalid input is rejected by Zod before the handler runs (SDK returns a protocol
  error). Domain "misses" (not found / ambiguous) are successful results with explanatory fields,
  so the LLM can adapt rather than seeing an exception.

---

## 6. Test plan (vitest)

**`parser.test.ts`**
- Parses `# FORMAT` → correct columns; parses `# VERSION`.
- Schema-agnostic: a fixture with a *different* FORMAT header yields differently-named fields with
  no code change.
- Unknown VERSION → warning emitted, rows still parsed (no throw).
- Malformed row (wrong field count) → skipped, warning carries the right line number; good rows
  around it survive.
- Ignores comments and blank lines; trims fields.
- Missing `# FORMAT` → throws.

**`repository.test.ts`**
- Index construction: lookups by id, normalized cve_id, title, vendor_id.
- Vendor join enrichment attaches the right vendor; orphan `vendor_id` → record kept, `vendor:
  null`, warning logged.
- Numeric coercion (`cvss_score`, `founded`); `affected_versions` preserved verbatim.
- `search` filter combinations: severity+status, cvss range, date range, keyword, vendor_name;
  empty filter returns all; limit respected.
- `getStatistics` correctness against the known 20-row dataset (e.g. open_critical_count,
  avg_cvss, highest = Log4Shell 10.0).

**`tools.test.ts`**
- Zod validation rejects bad input (out-of-range cvss, bad enum).
- `get_vulnerability` ladder: internal id, prefixed/unprefixed/lowercase cve_id, exact title,
  single partial (`matched_by: partial_title`), ambiguous (`dirty` → COW + Pipe → candidates),
  zero (suggestions + hint).
- `search_vulnerabilities` combinable filters via the registered handler; output shape/sort.
- `list_vendors` counts & breakdown; `get_vendor_profile` by id and by name incl. not-found.

Fixtures: a tiny in-memory dataset plus `.db` files exercising a malformed row, an orphan
`vendor_id`, and an unsupported VERSION. Tools tested by calling handlers against a repo built
from fixtures (no live stdio needed).

---

## 7. Phase 2 — CLI agent (`agent/cli.ts`, Gemini)

An agentic CLI that answers NL questions by calling the MCP server's tools.

- **Transport:** spawn the built server as a subprocess over stdio using the MCP SDK `Client` +
  `StdioClientTransport` (`command: node, args: [dist/index.js]`). The agent is a real MCP client
  — proves the server works end-to-end.
- **Model:** `@google/genai`, `GEMINI_API_KEY` from env. List the server's tools via
  `client.listTools()`, convert each tool's JSON Schema into a Gemini `functionDeclaration`.
- **Loop:** user question → Gemini → if `functionCall`s, dispatch each to `client.callTool()`,
  feed `functionResponse`s back → repeat until the model returns text. Supports multiple/chained
  tool calls (e.g. "critical open vulns in Linux Kernel" → search + vendor profile).
- **UX:** `npm run agent -- "your question"` or a stdin REPL. Tool-call trace printed to stderr
  (stdout = final answer), so the wrapping stays consistent with the server's stderr discipline.
- Graceful message if `GEMINI_API_KEY` is unset — server + Claude Desktop path still works
  without it.

---

## 8. README (deliverable)

- Setup: `npm install`, `npm run build`, `npm test`.
- Tool reference: one section per tool with input schema + example.
- **Design decisions** paragraph, incl.: schema-agnostic parser (domain knowledge in repo, not
  parser); Map indexing for scale; `affected_versions` kept free text; stderr-only logging; and
  the `get_vulnerability` strict→fuzzy ladder — *"resolves identifiers through a strict-to-fuzzy
  ladder and returns disambiguation candidates rather than guessing, because the consumer is an
  LLM: ambiguity should surface as a follow-up question, not a silent wrong answer."*
- **"With more time"** paragraph (per assignment): richer version-range reasoning, fuzzy vendor
  search, pagination cursors, a resources/prompts layer, watch-mode reload on file change.
- **Claude Desktop config snippet:**

```json
{
  "mcpServers": {
    "vuln-registry": {
      "command": "node",
      "args": ["C:/absolute/path/to/vuln-registry-mcp/dist/index.js"]
    }
  }
}
```

Path is absolute; server auto-loads `data/*.db` (override via `VULN_DATA_DIR`). Restart Claude
Desktop after editing `claude_desktop_config.json`.

---

## 9. Build order (milestones — commit after each, imperative messages)

1. Scaffold: `package.json`, `tsconfig.json`, `vitest.config.ts`, `logger.ts`, `config.ts`.
2. Parser + `parser.test.ts`.
3. Repository (mapping, indexes, join/orphan validation) + `repository.test.ts`.
4. MCP server + five tools + `tools.test.ts`.
5. `index.ts` stdio entry + startup summary; manual smoke via MCP Inspector / Claude Desktop.
6. README (tools, design notes, Claude Desktop snippet).
7. Phase 2 Gemini CLI agent.

---

## 10. Verification

- `npm test` green (parser, repository, tools).
- `npm run build` clean under `strict`.
- `grep -rn "console.log" src` → no hits (stdout discipline).
- Smoke: `npx @modelcontextprotocol/inspector node dist/index.js`, call each tool; confirm
  startup warnings for the orphan/malformed fixtures appear on **stderr** only.
- End-to-end: add to Claude Desktop and ask "How many critical vulnerabilities are still open?"
  / "What is the CVSS score of Log4Shell?"; if `GEMINI_API_KEY` set, same via `npm run agent`.

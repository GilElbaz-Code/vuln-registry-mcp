# Vulnerability Registry MCP Server

An MCP server that wraps a legacy, pipe-delimited vulnerability/vendor text
database (`data/vendors.db`, `data/vulnerabilities.db`) and exposes it as five
tools any MCP-compatible client — Claude Desktop, a custom agent, etc. — can
call to answer natural-language questions like *"How many critical
vulnerabilities are still open?"* or *"What is the CVSS score of Log4Shell?"*

## Setup

Requires Node.js 20+.

```bash
npm install
npm run build   # compiles src/ -> dist/
npm test        # runs the vitest suite
```

Run the server directly (over stdio) for local testing:

```bash
npm run dev      # tsx src/index.ts — no build step needed
# or, after building:
npm start        # node dist/index.js
```

The server loads `data/vendors.db` and `data/vulnerabilities.db` relative to
the project root by default. Override the directory with `VULN_DATA_DIR` if
you want to point it at a different copy of the files.

On startup it logs a one-line summary (vendor/vulnerability counts, orphaned
`vendor_id` references) plus any parse warnings — all to **stderr**. Nothing
but MCP JSON-RPC ever goes to stdout, so the server is safe to pipe directly
into any stdio-based MCP client.

## Tools

All tool inputs are validated with Zod before the handler ever runs; a
missing filesystem file or unparseable metadata header will fail the server
at startup, but bad *data rows* are skipped (with a stderr warning) rather
than crashing the process.

### `search_vulnerabilities`

Search with combinable, all-optional filters — they combine with AND, so an
empty call returns the whole registry (capped by `limit`). Results are
sorted by CVSS score (desc), then publish date (desc).

| field              | type                                              | notes                                    |
|--------------------|----------------------------------------------------|-------------------------------------------|
| `severity`         | `("critical"\|"high"\|"medium"\|"low")[]`         | matches any of the given severities       |
| `status`           | `"open"\|"patched"`                               |                                            |
| `vendor_id`        | `string`                                          | exact, e.g. `V2`                          |
| `vendor_name`      | `string`                                          | case-insensitive substring                |
| `keyword`          | `string`                                          | case-insensitive substring on title/CVE id|
| `min_cvss`/`max_cvss` | `number` (0–10)                                | inclusive range                           |
| `published_after`/`published_before` | `string` (`YYYY-MM-DD`)          | inclusive range                           |
| `limit`            | `number` (default 50, max 200)                    | applied after sorting                     |

```json
{ "severity": ["critical"], "status": "open" }
```
```json
{
  "count": 2,
  "total_matched": 2,
  "results": [
    { "id": "CVE020", "cve_id": "CVE-2024-21762", "title": "Fortinet SSL VPN OOB", "vendor_id": "V4",
      "severity": "critical", "cvss_score": 9.6, "status": "open", "vendor": { "name": "Google", "...": "..." }, "...": "..." },
    { "id": "CVE019", "cve_id": "CVE-2024-27198", "title": "TeamCity Auth Bypass", "...": "..." }
  ]
}
```

### `get_vulnerability`

Looks up **one** vulnerability by CVE id, internal id, or title. See
[design decisions](#design-decisions) for why this resolves through a
strict-to-fuzzy ladder instead of a single fuzzy search.

| field        | type     | notes                                              |
|--------------|----------|-----------------------------------------------------|
| `identifier` | `string` | CVE id, internal id (`CVE001`), or title            |

```json
{ "identifier": "cve-2021-44228" }
```
```json
{ "found": true, "matched_by": "cve_id", "vulnerability": { "id": "CVE001", "title": "Log4Shell", "cvss_score": 10, "...": "..." } }
```

Ambiguous or unmatched identifiers don't guess:

```json
{ "found": false, "ambiguous": true, "candidates": [{ "id": "CVE008", "title": "PrintNightmare" }, { "id": "CVE010", "title": "PrintNightmare RCE" }] }
```
```json
{ "found": false, "ambiguous": false, "suggestions": [...], "hint": "No match for \"...\". Similar entries: ... For broader queries use search_vulnerabilities." }
```

### `list_vendors`

Lists every vendor with its vulnerability count, open count, and severity
breakdown.

| field     | type                    | notes                                    |
|-----------|-------------------------|--------------------------------------------|
| `sort_by` | `"vuln_count"\|"name"`  | default `vuln_count` (descending)          |

```json
{ "sort_by": "vuln_count" }
```
```json
{ "count": 5, "vendors": [{ "id": "V2", "name": "Apache Software Foundation", "vuln_count": 4, "open_count": 0, "severity_breakdown": { "critical": 3, "high": 1, "medium": 0, "low": 0 }, "...": "..." }] }
```

### `get_vendor_profile`

Looks up **one** vendor by id or name (exact or partial — same
strict-to-fuzzy philosophy as `get_vulnerability`) and returns its full
vulnerability list plus stats.

| field        | type     | notes                                |
|--------------|----------|---------------------------------------|
| `identifier` | `string` | vendor id (`V2`) or name, exact/partial|

```json
{ "identifier": "apache" }
```
```json
{
  "found": true, "matched_by": "partial_name", "id": "V2", "name": "Apache Software Foundation",
  "stats": { "total": 4, "open": 0, "patched": 4, "by_severity": { "critical": 3, "high": 1, "medium": 0, "low": 0 }, "avg_cvss": 9.28, "max_cvss": 10 },
  "vulnerabilities": [ "..." ]
}
```

### `get_statistics`

Registry-wide headline numbers, with an optional grouped breakdown.

| field      | type                              | notes                                  |
|------------|------------------------------------|------------------------------------------|
| `group_by` | `"severity"\|"status"\|"vendor"`  | optional; adds a `breakdown` field       |

```json
{ "group_by": "vendor" }
```
```json
{
  "total_vulnerabilities": 20, "by_severity": { "critical": 9, "high": 10, "medium": 1, "low": 0 },
  "by_status": { "patched": 16, "open": 4 }, "open_critical_count": 2, "avg_cvss": 8.44,
  "highest": { "id": "CVE001", "title": "Log4Shell", "cvss_score": 10 },
  "published_date_range": { "earliest": "2014-04-07", "latest": "2024-03-04" },
  "vendor_count": 5, "orphan_count": 0,
  "group_by": "vendor", "breakdown": [{ "vendor_id": "V1", "vendor_name": "Microsoft", "count": 5 }, "..."]
}
```

## Claude Desktop configuration

Add this to `claude_desktop_config.json` (adjust the path to where you
cloned the repo), then restart Claude Desktop:

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

Run `npm run build` first — the config points at the compiled `dist/index.js`,
not the TypeScript source.

## Phase 2 — CLI agent

An optional natural-language CLI agent (`agent/cli.ts`) that spawns the MCP
server as a real subprocess over stdio, lists its tools, and drives a
[Gemini](https://ai.google.dev/) function-calling loop on top of them —
proving the server works with a real MCP client, not just Claude Desktop.

```bash
export GEMINI_API_KEY=your-key-here
npm run agent -- "How many critical vulnerabilities are still open?"
```

Without `npm run agent -- "question"` (a positional arg), it starts an
interactive stdin loop instead. Tool-call tracing goes to stderr; the final
answer is the only thing printed to stdout. If `GEMINI_API_KEY` isn't set,
the agent exits with a clear message — the MCP server and Claude Desktop
path work fully without it.

## Design decisions

- **Schema-agnostic parser.** The parser (`src/parser/`) knows nothing about
  vendors or vulnerabilities — it derives column names from the `# FORMAT`
  header at runtime and turns each row into a `Record<string,string>`. All
  domain knowledge (which columns mean what, numeric coercion, the vendor
  join) lives one layer up, in the repository. Adding a column in a future
  format version requires zero parser changes.
- **Never crash on bad data.** An unknown `# VERSION` logs a warning and
  keeps parsing (the format may evolve). A malformed row (wrong field count,
  non-numeric `cvss_score`/`founded`) is skipped with a line-numbered stderr
  warning, not a thrown exception — one bad row in a growing legacy file
  shouldn't take the whole registry down.
- **`affected_versions` stays free text.** It's never parsed into semver;
  the data doesn't follow one consistent version-range grammar (`"2.0-2.14.1"`,
  `"Windows 7-2008 R2"`, `"SSLv3"`), and getting that wrong silently would be
  worse than not parsing it at all.
- **Map-based indexing.** The repository builds `Map`s by id, cve_id,
  (normalized) title, and vendor_id once at load time, so lookups and the
  vendor join are O(1) instead of repeated `array.filter` scans — needed
  since "the database is expected to grow" per the assignment.
- **Vendor join keeps orphans.** If a vulnerability's `vendor_id` doesn't
  resolve to a known vendor, it's logged as an orphan at startup and kept in
  the registry with `vendor: null` on enrichment, rather than being dropped —
  a security team shouldn't lose visibility into a CVE just because its
  vendor record is missing.
- **`get_vulnerability` resolves through a strict-to-fuzzy ladder** — exact
  internal id, exact CVE id (prefix/case-insensitive), exact title, then
  partial title — stopping at the first hit. A single partial match is
  returned but flagged (`matched_by: "partial_title"`); *multiple* partial
  matches return disambiguation candidates instead of picking one. The
  consumer here is an LLM, and a silent wrong guess (e.g. "PrintNightmare"
  auto-resolving to "PrintNightmare RCE", a different CVE with a different
  score) is worse than a follow-up question. `get_vendor_profile` applies
  the same philosophy to vendor id/name lookup.
- **stdout is JSON-RPC only.** All logging (`src/logger.ts`) goes to stderr;
  this is enforced structurally rather than by convention, since anything on
  stdout would corrupt the MCP transport.

## What I'd build differently with more time

- Real version-range reasoning for `affected_versions` (e.g. "is 5.3.2
  affected?") instead of treating it as opaque text — hard to do generally
  given how inconsistent the free-text formats are across rows, but doable
  per-vendor with more time.
- Fuzzy vendor/title matching beyond substring + token-overlap (e.g. proper
  edit-distance ranking) once the dataset is large enough that substring
  matching starts returning too many candidates.
- Cursor-based pagination for `search_vulnerabilities` instead of a flat
  `limit`, once "thousands of records" stops being small enough to sort
  in memory on every call.
- A file-watcher to reload the in-memory registry when the `.db` files
  change on disk, instead of requiring a server restart.
- MCP resources/prompts (not just tools) — e.g. a prompt template for
  "triage this vendor's open criticals" — to give clients richer starting
  points than raw tool calls.

# Vulnerability Registry MCP Server (Deloitte take-home)

## Context
Read docs/ASSIGNMENT.md first. Data files in data/ use a custom
pipe-delimited format with a # FORMAT metadata header and # VERSION field.

## Stack
TypeScript (strict mode), @modelcontextprotocol/sdk, Zod, vitest.
Node 20+. No other runtime dependencies without asking me.

## Commands
- npm test          # vitest, must pass before any commit
- npm run build     # tsc
- npm run dev       # start MCP server over stdio

## Hard rules
- Parser must be schema-agnostic: derive column names from the FORMAT
  metadata line at runtime, never hardcode column indices. Warn (don't
  crash) on unknown VERSION.
- ALL logging goes to stderr only — stdout is the MCP JSON-RPC channel.
- affected_versions stays free text; do not parse it into semver.
- Skip malformed data rows with a stderr warning + line number, never crash.
- On startup, validate vendor_id references; log orphans, keep the record.
- Commit after each working milestone, imperative commit messages.
- Use Maps for indexing (by id, by vendor_id) — no repeated array.filter scans.
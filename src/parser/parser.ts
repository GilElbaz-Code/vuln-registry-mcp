import type { ParsedFile, ParsedRow, ParseWarning } from "./types.js";

const FORMAT_PREFIX = "# FORMAT:";
const VERSION_PREFIX = "# VERSION:";

export const SUPPORTED_VERSIONS = ["1.0"];

export class ParseError extends Error {}

/**
 * Parses a generic pipe-delimited "# FORMAT" / "# VERSION" text file into
 * named rows. Column names come entirely from the FORMAT header at runtime —
 * this function has no knowledge of what any column means.
 */
export function parseDbFile(text: string, sourceName: string): ParsedFile {
  const lines = text.split(/\r?\n/);

  let columns: string[] | null = null;
  let version: string | null = null;
  const rows: ParsedRow[] = [];
  const rowLines: number[] = [];
  const warnings: ParseWarning[] = [];

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i] ?? "";
    const line = rawLine.trim();
    const lineNumber = i + 1;

    if (line.length === 0) {
      continue;
    }

    if (line.startsWith("#")) {
      if (line.startsWith(FORMAT_PREFIX)) {
        columns = line
          .slice(FORMAT_PREFIX.length)
          .split("|")
          .map((c) => c.trim());
      } else if (line.startsWith(VERSION_PREFIX)) {
        version = line.slice(VERSION_PREFIX.length).trim();
      }
      continue;
    }

    if (columns === null) {
      throw new ParseError(
        `${sourceName}: missing "${FORMAT_PREFIX}" metadata line before first data row (line ${lineNumber})`,
      );
    }

    const fields = line.split("|").map((f) => f.trim());
    if (fields.length !== columns.length) {
      warnings.push({
        line: lineNumber,
        message: `${sourceName}:${lineNumber}: skipped malformed row — expected ${columns.length} fields, got ${fields.length}`,
      });
      continue;
    }

    const row: ParsedRow = {};
    for (let c = 0; c < columns.length; c++) {
      row[columns[c] as string] = fields[c] as string;
    }
    rows.push(row);
    rowLines.push(lineNumber);
  }

  if (columns === null) {
    throw new ParseError(`${sourceName}: missing "${FORMAT_PREFIX}" metadata line — file has no data schema`);
  }

  if (version === null) {
    warnings.push({
      line: 0,
      message: `${sourceName}: missing "${VERSION_PREFIX}" metadata line`,
    });
  } else if (!SUPPORTED_VERSIONS.includes(version)) {
    warnings.push({
      line: 0,
      message: `${sourceName}: unsupported VERSION "${version}" (supported: ${SUPPORTED_VERSIONS.join(", ")}) — attempting to parse anyway`,
    });
  }

  return { sourceName, version, columns, rows, rowLines, warnings };
}

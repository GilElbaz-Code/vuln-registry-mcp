import { describe, expect, it } from "vitest";
import { ParseError, parseDbFile } from "../src/parser/parser.js";

const VENDORS_SAMPLE = `# METADATA
# FORMAT: type|id|name|category|hq|founded
# VERSION: 1.0

VENDOR|V1|Microsoft|Software|Redmond, WA|1975
VENDOR|V2|Apache Software Foundation|Open Source|Wilmington, DE|1999
`;

describe("parseDbFile", () => {
  it("derives columns from the FORMAT header and parses rows by name", () => {
    const result = parseDbFile(VENDORS_SAMPLE, "vendors.db");

    expect(result.columns).toEqual(["type", "id", "name", "category", "hq", "founded"]);
    expect(result.version).toBe("1.0");
    expect(result.rows).toHaveLength(2);
    expect(result.rows[0]).toEqual({
      type: "VENDOR",
      id: "V1",
      name: "Microsoft",
      category: "Software",
      hq: "Redmond, WA",
      founded: "1975",
    });
    expect(result.warnings).toHaveLength(0);
    expect(result.rowLines).toEqual([5, 6]);
  });

  it("is schema-agnostic: a different FORMAT header yields differently named fields with no code change", () => {
    const sample = `# FORMAT: sku|price|label
# VERSION: 1.0

ITEM|9.99|Widget
`;
    const result = parseDbFile(sample, "items.db");

    expect(result.columns).toEqual(["sku", "price", "label"]);
    expect(result.rows[0]).toEqual({ sku: "ITEM", price: "9.99", label: "Widget" });
  });

  it("warns but does not throw on an unknown VERSION, and still parses rows", () => {
    const sample = `# FORMAT: id|name
# VERSION: 2.7

X|Y
`;
    const result = parseDbFile(sample, "future.db");

    expect(result.version).toBe("2.7");
    expect(result.rows).toEqual([{ id: "X", name: "Y" }]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]?.message).toMatch(/unsupported VERSION "2.7"/);
  });

  it("skips a malformed row (wrong field count) with a stderr-bound warning carrying the line number, and keeps parsing surrounding rows", () => {
    const sample = `# FORMAT: id|name|value
# VERSION: 1.0

R1|Good|1
R2|BrokenRow
R3|AlsoGood|3
`;
    const result = parseDbFile(sample, "broken.db");

    expect(result.rows).toEqual([
      { id: "R1", name: "Good", value: "1" },
      { id: "R3", name: "AlsoGood", value: "3" },
    ]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]?.line).toBe(5);
    expect(result.warnings[0]?.message).toMatch(/skipped malformed row/);
  });

  it("ignores comment and blank lines, and trims whitespace from fields", () => {
    const sample = `# some other comment
# FORMAT: id|name
# VERSION: 1.0

  R1  |   Padded Name

# another comment
R2|Second
`;
    const result = parseDbFile(sample, "padded.db");

    expect(result.rows).toEqual([
      { id: "R1", name: "Padded Name" },
      { id: "R2", name: "Second" },
    ]);
  });

  it("skips data rows that appear before the FORMAT header, with a line-numbered warning", () => {
    const sample = `STRAY|row|above|header
# FORMAT: id|name
# VERSION: 1.0
R1|Good
`;
    const result = parseDbFile(sample, "stray.db");

    expect(result.rows).toEqual([{ id: "R1", name: "Good" }]);
    const warning = result.warnings.find((w) => /before/.test(w.message));
    expect(warning?.line).toBe(1);
  });

  it("throws a ParseError when the FORMAT metadata line is missing", () => {
    const sample = `# VERSION: 1.0

R1|Good
`;
    expect(() => parseDbFile(sample, "noformat.db")).toThrow(ParseError);
  });
});

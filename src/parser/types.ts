export type ParsedRow = Record<string, string>;

export interface ParseWarning {
  line: number;
  message: string;
}

export interface ParsedFile {
  sourceName: string;
  version: string | null;
  columns: string[];
  rows: ParsedRow[];
  warnings: ParseWarning[];
}

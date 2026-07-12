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
  /** Source line number for rows[i], for warnings raised on this row downstream (e.g. numeric coercion). */
  rowLines: number[];
  warnings: ParseWarning[];
}

import { z } from "zod";
import type { VulnRepository } from "../repository/repository.js";
import { jsonResult } from "./json-result.js";

export const listVendorsShape = {
  sort_by: z
    .enum(["vuln_count", "name"])
    .default("vuln_count")
    .describe("Sort vendors by number of vulnerabilities (descending) or alphabetically by name"),
};

const ListVendorsInput = z.object(listVendorsShape);
export type ListVendorsInput = z.infer<typeof ListVendorsInput>;

export function listVendors(repo: VulnRepository, input: ListVendorsInput) {
  const vendors = repo.listVendors(input.sort_by);
  return jsonResult({ count: vendors.length, vendors });
}

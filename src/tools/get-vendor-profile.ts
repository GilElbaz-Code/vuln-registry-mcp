import { z } from "zod";
import type { VulnRepository } from "../repository/repository.js";
import { jsonResult } from "./json-result.js";
import { resolveVendor } from "./resolution.js";

export const getVendorProfileShape = {
  identifier: z
    .string()
    .min(1)
    .describe("A vendor's internal id (e.g. V2) or name, exact or partial (e.g. Apache)"),
};

const GetVendorProfileInput = z.object(getVendorProfileShape);
export type GetVendorProfileInput = z.infer<typeof GetVendorProfileInput>;

export function getVendorProfile(repo: VulnRepository, input: GetVendorProfileInput) {
  const resolution = resolveVendor(repo, input.identifier);
  if (!resolution.found) {
    return jsonResult(resolution);
  }

  const profile = repo.buildVendorProfile(resolution.vendor);
  return jsonResult({ found: true, matched_by: resolution.matched_by, ...profile });
}

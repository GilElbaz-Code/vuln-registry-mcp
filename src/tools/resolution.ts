import type { VulnRepository } from "../repository/repository.js";
import type { EnrichedVulnerability, Vendor } from "../repository/types.js";

const CVE_PATTERN = /^(?:cve-)?(\d{4}-\d{4,})$/i;

/** Canonicalizes a user-supplied CVE identifier to "CVE-YYYY-NNNN…", or null if it isn't CVE-shaped. */
export function normalizeCveId(identifier: string): string | null {
  const match = identifier.trim().match(CVE_PATTERN);
  if (!match) return null;
  return `CVE-${match[1]}`.toUpperCase();
}

function tokenize(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function topSuggestions<T>(query: string, items: T[], getText: (item: T) => string, limit = 3): T[] {
  // Tokenize the query once; only candidates are tokenized inside the scan.
  const queryTokens = new Set(tokenize(query));
  if (queryTokens.size === 0) return [];

  const scored: Array<{ item: T; score: number }> = [];
  for (const item of items) {
    let overlap = 0;
    for (const token of tokenize(getText(item))) {
      if (queryTokens.has(token)) overlap++;
    }
    if (overlap > 0) scored.push({ item, score: overlap });
  }

  return scored
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((s) => s.item);
}

interface VulnCandidate {
  id: string;
  cve_id: string;
  title: string;
}

export type VulnResolution =
  | { found: true; matched_by: "id" | "cve_id" | "title" | "partial_title"; vulnerability: EnrichedVulnerability }
  | { found: false; ambiguous: true; candidates: VulnCandidate[] }
  | { found: false; ambiguous: false; suggestions: VulnCandidate[]; hint: string };

/**
 * Resolves a caller-supplied identifier to a vulnerability through a strict-to-fuzzy
 * ladder, stopping at the first hit. Ambiguous fuzzy matches are surfaced as
 * candidates rather than silently picked, since the caller is an LLM and a wrong
 * guess (e.g. "PrintNightmare" -> "PrintNightmare RCE") is worse than a follow-up.
 */
export function resolveVulnerability(repo: VulnRepository, identifier: string): VulnResolution {
  const trimmed = identifier.trim();

  const byId = repo.getVulnById(trimmed);
  if (byId) return { found: true, matched_by: "id", vulnerability: repo.enrich(byId) };

  const normalizedCve = normalizeCveId(trimmed);
  if (normalizedCve) {
    const byCve = repo.getVulnByCveId(normalizedCve);
    if (byCve) return { found: true, matched_by: "cve_id", vulnerability: repo.enrich(byCve) };
  }

  const byTitle = repo.getVulnByTitle(trimmed);
  if (byTitle) return { found: true, matched_by: "title", vulnerability: repo.enrich(byTitle) };

  const partialMatches = repo.findVulnsByTitleContaining(trimmed);
  if (partialMatches.length === 1) {
    return { found: true, matched_by: "partial_title", vulnerability: repo.enrich(partialMatches[0]!) };
  }
  if (partialMatches.length > 1) {
    return {
      found: false,
      ambiguous: true,
      candidates: partialMatches.map((v) => ({ id: v.id, cve_id: v.cve_id, title: v.title })),
    };
  }

  const suggestions = topSuggestions(trimmed, repo.getAllVulnerabilities(), (v) => v.title).map((v) => ({
    id: v.id,
    cve_id: v.cve_id,
    title: v.title,
  }));

  return {
    found: false,
    ambiguous: false,
    suggestions,
    hint:
      suggestions.length > 0
        ? `No match for "${identifier}". Similar entries: ${suggestions.map((s) => s.title).join(", ")}. For broader queries use search_vulnerabilities.`
        : `No match for "${identifier}". For broader queries use search_vulnerabilities.`,
  };
}

interface VendorCandidate {
  id: string;
  name: string;
}

export type VendorResolution =
  | { found: true; matched_by: "id" | "name" | "partial_name"; vendor: Vendor }
  | { found: false; ambiguous: true; candidates: VendorCandidate[] }
  | { found: false; ambiguous: false; suggestions: VendorCandidate[]; hint: string };

/** Same strict-to-fuzzy philosophy as resolveVulnerability, applied to vendor id/name lookup. */
export function resolveVendor(repo: VulnRepository, identifier: string): VendorResolution {
  const trimmed = identifier.trim();

  const byId = repo.getVendorById(trimmed);
  if (byId) return { found: true, matched_by: "id", vendor: byId };

  const allVendors = repo.getAllVendors();
  const exactName = allVendors.find((v) => v.name.toLowerCase() === trimmed.toLowerCase());
  if (exactName) return { found: true, matched_by: "name", vendor: exactName };

  const partialMatches = repo.findVendorsByNameContaining(trimmed);
  if (partialMatches.length === 1) {
    return { found: true, matched_by: "partial_name", vendor: partialMatches[0]! };
  }
  if (partialMatches.length > 1) {
    return {
      found: false,
      ambiguous: true,
      candidates: partialMatches.map((v) => ({ id: v.id, name: v.name })),
    };
  }

  const suggestions = topSuggestions(trimmed, allVendors, (v) => v.name).map((v) => ({ id: v.id, name: v.name }));

  return {
    found: false,
    ambiguous: false,
    suggestions,
    hint:
      suggestions.length > 0
        ? `No vendor match for "${identifier}". Similar entries: ${suggestions.map((s) => s.name).join(", ")}. For a full list use list_vendors.`
        : `No vendor match for "${identifier}". For a full list use list_vendors.`,
  };
}

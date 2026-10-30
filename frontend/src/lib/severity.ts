import type { Severity } from "./api";

export type CvssBand = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Display order and CVSS v3 base-score ranges for the results sub-sections. */
export const CVSS_BANDS: { band: CvssBand; range: string }[] = [
  { band: "LOW", range: "0.1–3.9" },
  { band: "MEDIUM", range: "4.0–6.9" },
  { band: "HIGH", range: "7.0–8.9" },
  { band: "CRITICAL", range: "9.0–10.0" },
];

/**
 * Buckets a finding by CVSS v3 base score. Scores below 4.0 (including 0 and below) are LOW.
 * When the score is missing (null/undefined/NaN), falls back to the Nuclei severity:
 * critical -> CRITICAL, high -> HIGH, medium -> MEDIUM, anything else (low, info, unknown) -> LOW.
 */
export function cvssBand(score: number | null | undefined, fallbackSeverity?: Severity | string): CvssBand {
  if (typeof score === "number" && Number.isFinite(score)) {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    return "LOW";
  }
  switch (fallbackSeverity?.toLowerCase()) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    default:
      return "LOW";
  }
}

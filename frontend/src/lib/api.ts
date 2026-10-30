// Typed client for the VMDR API. Paths are relative (/api) so the same build works behind nginx or the Vite proxy.

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type TargetStatus = "ACTIVE" | "PAUSED" | "ARCHIVED";
export type VulnStatus = "OPEN" | "FALSE_POSITIVE" | "ACCEPTED_RISK" | "RESOLVED";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";
export type Reachability = "UNKNOWN" | "REACHABLE" | "UNREACHABLE";
export type LastResult = "CLEAN" | "VULNERABLE";
/** Filter values accepted by GET /api/targets?result= */
export type ResultFilter = "CLEAN" | "VULNERABLE" | "UNREACHABLE" | "UNSCANNED";

export interface VulnCounts {
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Target {
  id: number;
  url: string;
  host: string;
  domain_root: string;
  tags: string[];
  status: TargetStatus;
  notes: string | null;
  created_at: string;
  updated_at: string;
  last_scanned_at: string | null;
  last_scan_status: string | null;
  risk: RiskLevel;
  vuln_counts: VulnCounts;
  reachability: Reachability;
  last_probe_error: string | null;
  consecutive_probe_failures: number;
  last_result: LastResult | null;
  last_open_findings: number;
}

export interface TargetPage {
  items: Target[];
  total: number;
  page: number;
  page_size: number;
}

export interface BulkImportResult {
  created: Target[];
  skipped_duplicates: string[];
  invalid: { input: string; error: string }[];
}

export interface DomainGroup {
  domain_root: string;
  count: number;
}

/** CVE publication window in years; null or omitted means all CVE years. */
export type CveYears = 1 | 2 | 3 | 5 | 10;

export interface ScanRun {
  id: number;
  scope: string;
  target_id: number | null;
  severities: string;
  cve_years?: CveYears | null;
  status: string;
  requested_by: string;
  targets_count: number;
  findings_count: number;
  new_findings: number;
  resolved_findings: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  unreachable_count?: number;
  cancel_requested?: boolean;
  targets_scanned?: number;
  chunks_total?: number;
  chunks_done?: number;
  /** Set once the run has finished. */
  duration_seconds?: number | null;
}

export type RunStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";

export interface ActiveTarget {
  id: number;
  url: string;
  host: string;
  reachability: Reachability;
}

/** Response of GET /api/scans/status (live view used by the Overview scan panel). */
export interface LiveScanStatus extends Omit<ScanStatus, "logs"> {
  active_targets: ActiveTarget[];
  /** Server clock (ISO string), used to correct the client clock for the elapsed timer. */
  server_time: string | null;
}

export interface LogLine {
  id: number;
  run_id: number | null;
  ts: string;
  level: string;
  message: string;
}

export interface ScanStatus {
  state: "IDLE" | "SCANNING" | "UPDATING_TEMPLATES" | "OFFLINE";
  worker_online: boolean;
  heartbeat_at: string | null;
  current_run: ScanRun | null;
  live_findings: number | null;
  queue_length: number;
  templates: { status: string; updated_at: string | null; error: string | null; update_requested: boolean };
  recent_runs: ScanRun[];
  logs: LogLine[];
}

export interface Vulnerability {
  id: number;
  fingerprint: string;
  target_id: number;
  target_url: string;
  domain_root: string;
  template_id: string;
  cve_id: string | null;
  name: string;
  severity: Severity;
  cvss_score: number | null;
  matched_at: string;
  matcher_name: string | null;
  curl_command: string | null;
  description: string | null;
  remediation: string | null;
  request: string | null;
  response: string | null;
  tags: string[];
  status: VulnStatus;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  missed_scans: number;
}

export interface VulnPage {
  items: Vulnerability[];
  total: number;
  page: number;
  page_size: number;
}

export interface Stats {
  total_monitored_endpoints: number;
  active_targets: number;
  paused_targets: number;
  archived_targets: number;
  active_critical: number;
  active_high: number;
  severity_distribution: Record<string, number>;
  scans_run_last_24h: number;
  new_findings_last_24h: number;
  new_findings_previous_24h: number;
  spike: boolean;
  mttr_hours: number | null;
  last_7_days: { date: string; new_findings: number; critical_high: number }[];
  scanner: ScanStatus;
}

const KEY_STORAGE = "vmdr_api_key";

export function getApiKey(): string {
  try {
    return localStorage.getItem(KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(value: string): void {
  try {
    if (value) localStorage.setItem(KEY_STORAGE, value);
    else localStorage.removeItem(KEY_STORAGE);
  } catch {
    /* storage unavailable (private mode); the key simply isn't remembered */
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const key = getApiKey();
  if (key) headers["X-API-Key"] = key;

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") message = data.detail;
      else if (data.detail) message = JSON.stringify(data.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new Error(message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  patch: <T,>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: (path: string) => request<void>("DELETE", path),
};

export function getLiveScanStatus(): Promise<LiveScanStatus> {
  return api.get<LiveScanStatus>("/scans/status");
}

export function cancelScanRun(runId: number): Promise<ScanRun> {
  return api.post<ScanRun>(`/scans/${runId}/cancel`);
}

export function triggerTargetsScan(targetIds: number[], cveYears?: CveYears | null): Promise<ScanRun> {
  return api.post<ScanRun>("/scans/trigger", { scope: "targets", target_ids: targetIds, cve_years: cveYears ?? null });
}

/** Every ACTIVE target, walking the paginated /targets list (page_size is capped at 200 by the API). */
export async function fetchActiveTargets(): Promise<Target[]> {
  const pageSize = 200;
  const all: Target[] = [];
  for (let page = 1; ; page++) {
    const res = await api.get<TargetPage>(`/targets?status=ACTIVE&page_size=${pageSize}&page=${page}`);
    all.push(...res.items);
    if (res.items.length < pageSize || all.length >= res.total) break;
  }
  return all;
}

/** Backend timestamps are naive UTC; append Z so the browser converts them to local time. */
export function parseTs(value: string | null | undefined): Date | null {
  if (!value) return null;
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value}Z`);
}

export function timeAgo(value: string | null | undefined): string {
  const d = parseTs(value);
  if (!d) return "never";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function formatDate(value: string | null | undefined): string {
  const d = parseTs(value);
  return d ? d.toLocaleString() : "—";
}

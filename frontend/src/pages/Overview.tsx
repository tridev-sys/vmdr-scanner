import { useEffect, useState, useCallback } from "react";
import { Activity, AlertTriangle, Globe, Loader2, RefreshCw, Play, ShieldAlert, TrendingUp } from "lucide-react";
import { Card, Button, ErrorText } from "../components/ui";
import { api, timeAgo, type Stats } from "../lib/api";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const BAR_COLOR: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

function StatCard({ label, value, icon: Icon, hint, tone }: {
  label: string;
  value: number | string;
  icon: typeof Globe;
  hint?: string;
  tone?: string;
}) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-slate-500">{label}</span>
        <Icon size={18} className={tone ?? "text-slate-400"} />
      </div>
      <div className="mt-3 text-3xl font-semibold tracking-tight">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </Card>
  );
}

function ScannerIndicator({ stats }: { stats: Stats }) {
  const s = stats.scanner;
  const map: Record<string, { label: string; cls: string }> = {
    IDLE: { label: "Idle", cls: "bg-slate-100 text-slate-700" },
    SCANNING: { label: "Scanning", cls: "bg-blue-100 text-blue-800" },
    UPDATING_TEMPLATES: { label: "Updating templates", cls: "bg-violet-100 text-violet-800" },
    OFFLINE: { label: "Worker offline", cls: "bg-red-100 text-red-800" },
  };
  const m = map[s.state] ?? map.IDLE;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${m.cls}`}>
      {(s.state === "SCANNING" || s.state === "UPDATING_TEMPLATES") && <Loader2 size={12} className="animate-spin" />}
      {m.label}
      {s.queue_length > 0 && <span className="text-slate-500">· {s.queue_length} queued</span>}
    </span>
  );
}

export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setStats(await api.get<Stats>("/stats"));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  // Poll faster while the worker is busy so the status indicator stays live.
  useEffect(() => {
    load();
    const interval = setInterval(load, stats?.scanner.state === "IDLE" ? 15000 : 3000);
    return () => clearInterval(interval);
  }, [load, stats?.scanner.state]);

  async function runFullScan() {
    setBusy(true);
    try {
      await api.post("/scans/trigger", { scope: "all" });
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function updateTemplates() {
    setBusy(true);
    try {
      await api.post("/scans/templates/update");
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!stats) return <div className="text-sm text-slate-500">{error ?? "Loading…"}</div>;

  const total = SEVERITIES.reduce((sum, s) => sum + (stats.severity_distribution[s] ?? 0), 0);
  const maxDay = Math.max(1, ...stats.last_7_days.map((d) => d.new_findings));
  const scanning = stats.scanner.state === "SCANNING" || stats.scanner.state === "UPDATING_TEMPLATES";

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-slate-500">Continuous Nuclei scanning across monitored endpoints.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <ScannerIndicator stats={stats} />
          <Button variant="secondary" onClick={updateTemplates} disabled={busy || scanning}>
            <RefreshCw size={14} /> Update templates
          </Button>
          <Button onClick={runFullScan} disabled={busy || scanning}>
            <Play size={14} /> Run full scan now
          </Button>
        </div>
      </header>

      <ErrorText error={error} />

      {stats.spike && (
        <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <AlertTriangle size={16} />
          New-findings spike: {stats.new_findings_last_24h} in the last 24h vs {stats.new_findings_previous_24h} before.
        </div>
      )}

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Monitored endpoints" value={stats.total_monitored_endpoints}
          icon={Globe} hint={`${stats.active_targets} active · ${stats.paused_targets} paused`} />
        <StatCard label="Active critical CVEs" value={stats.active_critical} icon={ShieldAlert}
          tone="text-sev-critical" hint="open findings" />
        <StatCard label="Active high CVEs" value={stats.active_high} icon={ShieldAlert}
          tone="text-sev-high" hint={stats.mttr_hours !== null ? `MTTR ${stats.mttr_hours}h (90d)` : "MTTR: no data yet"} />
        <StatCard label="Scans run (24h)" value={stats.scans_run_last_24h} icon={Activity}
          hint={`${stats.new_findings_last_24h} new findings today`} />
      </section>

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold">Open findings by severity</h2>
          <div className="space-y-3">
            {SEVERITIES.map((sev) => {
              const n = stats.severity_distribution[sev] ?? 0;
              const pct = total ? Math.round((n / total) * 100) : 0;
              return (
                <div key={sev} className="flex items-center gap-3 text-sm">
                  <span className="w-16 capitalize text-slate-600">{sev}</span>
                  <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-100">
                    <div className={`h-full rounded-full ${BAR_COLOR[sev]}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="w-10 text-right font-medium tabular-nums">{n}</span>
                </div>
              );
            })}
          </div>
        </Card>

        <Card className="p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold">New findings, last 7 days</h2>
            <TrendingUp size={16} className="text-slate-400" />
          </div>
          <div className="flex h-36 items-end gap-2">
            {stats.last_7_days.map((d) => (
              <div key={d.date} className="flex flex-1 flex-col items-center gap-1">
                <div className="flex w-full flex-1 items-end">
                  <div
                    className="w-full rounded-t bg-slate-800"
                    style={{ height: `${(d.new_findings / maxDay) * 100}%`, minHeight: d.new_findings ? 4 : 0 }}
                    title={`${d.new_findings} new (${d.critical_high} critical/high)`}
                  />
                </div>
                <span className="text-[10px] text-slate-400">{d.date.slice(5)}</span>
              </div>
            ))}
          </div>
        </Card>
      </section>

      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Recent scan runs</h2>
          <span className="text-xs text-slate-500">
            Templates: {stats.scanner.templates.status}
            {stats.scanner.templates.updated_at && ` · updated ${timeAgo(stats.scanner.templates.updated_at)}`}
          </span>
        </div>
        {stats.scanner.recent_runs.length === 0 ? (
          <p className="text-sm text-slate-500">No scans yet. Run one to populate findings.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr>
                  <th className="py-2 pr-4">Run</th>
                  <th className="py-2 pr-4">Scope</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4 text-right">Targets</th>
                  <th className="py-2 pr-4 text-right">Findings</th>
                  <th className="py-2 pr-4 text-right">New</th>
                  <th className="py-2 pr-4">Started</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {stats.scanner.recent_runs.map((r) => (
                  <tr key={r.id}>
                    <td className="py-2 pr-4 tabular-nums">#{r.id}</td>
                    <td className="py-2 pr-4">{r.scope === "TARGET" ? `target ${r.target_id}` : "all active"}</td>
                    <td className="py-2 pr-4">
                      <span className={r.status === "FAILED" ? "text-red-600" : r.status === "COMPLETED" ? "text-emerald-700" : "text-slate-600"}>
                        {r.status}
                      </span>
                      {r.error && <div className="max-w-xs truncate text-xs text-red-500" title={r.error}>{r.error}</div>}
                    </td>
                    <td className="py-2 pr-4 text-right tabular-nums">{r.targets_count}</td>
                    <td className="py-2 pr-4 text-right tabular-nums">{r.findings_count}</td>
                    <td className="py-2 pr-4 text-right tabular-nums">{r.new_findings}</td>
                    <td className="py-2 pr-4 text-slate-500">{timeAgo(r.started_at ?? r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {!stats.scanner.worker_online && (
        <p className="text-sm text-red-700">
          The scanner worker has not sent a heartbeat recently. Scans will queue but not run until it is started.
        </p>
      )}
    </div>
  );
}

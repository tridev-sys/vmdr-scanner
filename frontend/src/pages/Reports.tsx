import { useCallback, useEffect, useRef, useState } from "react";
import { Download } from "lucide-react";
import { Card, EmptyState, ErrorText } from "../components/ui";
import { formatDate, listReports, reportAvailable, reportDownloadUrl, type ReportItem } from "../lib/api";

const REFRESH_MS = 30000;

function sizeKb(bytes: number): string {
  return (bytes / 1024).toFixed(1);
}

function DownloadCell({ report, expired }: { report: ReportItem; expired: boolean }) {
  if (expired) return <span className="text-xs font-medium text-slate-400">Expired</span>;
  return (
    <a
      href={reportDownloadUrl(report.id)}
      download
      className="inline-flex items-center gap-1.5 rounded-lg bg-white px-3 py-1.5 text-sm font-medium text-slate-700 ring-1 ring-inset ring-slate-300 transition hover:bg-slate-50"
    >
      <Download size={14} />
      Download
    </a>
  );
}

export default function ReportsPage() {
  const [items, setItems] = useState<ReportItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expired, setExpired] = useState<Record<number, boolean>>({});
  const probed = useRef<Set<number>>(new Set());

  const load = useCallback(async () => {
    try {
      setItems(await listReports(50));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  // Probe each report once for expiry (410). Expired reports never come back, so caching is safe.
  useEffect(() => {
    if (!items) return;
    const pending = items.filter((r) => !probed.current.has(r.id));
    if (pending.length === 0) return;
    pending.forEach((r) => probed.current.add(r.id));
    Promise.all(pending.map(async (r) => [r.id, await reportAvailable(r.id)] as const)).then((results) => {
      setExpired((prev) => {
        const next = { ...prev };
        for (const [id, ok] of results) next[id] = !ok;
        return next;
      });
    });
  }, [items]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Reports</h1>
        <p className="text-sm text-slate-500">Scan reports with CVE and patch details. Kept for 5 days.</p>
      </div>

      <ErrorText error={error} />

      {!items ? (
        <Card className="p-6 text-sm text-slate-500">Loading…</Card>
      ) : items.length === 0 ? (
        <Card>
          <EmptyState>No reports yet. A report is created when a scan completes.</EmptyState>
        </Card>
      ) : (
        <>
          {/* Phone: one card per report */}
          <div className="space-y-3 md:hidden">
            {items.map((r) => (
              <Card key={r.id} className="space-y-3 p-4">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium" title={r.file_name}>{r.file_name}</div>
                  <div className="text-xs text-slate-500">Run #{r.run_id} · {formatDate(r.created_at)}</div>
                </div>
                <dl className="grid grid-cols-4 gap-2 text-center text-xs">
                  <div><dt className="text-slate-500">Targets</dt><dd className="font-medium tabular-nums">{r.targets_count}</dd></div>
                  <div><dt className="text-slate-500">Findings</dt><dd className="font-medium tabular-nums">{r.findings_count}</dd></div>
                  <div><dt className="text-slate-500">KB</dt><dd className="font-medium tabular-nums">{sizeKb(r.size_bytes)}</dd></div>
                  <div className="flex items-end justify-center"><DownloadCell report={r} expired={!!expired[r.id]} /></div>
                </dl>
              </Card>
            ))}
          </div>

          {/* Tablet and up: table */}
          <Card className="hidden overflow-hidden md:block">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Report</th>
                    <th className="px-4 py-3">Run</th>
                    <th className="px-4 py-3">Created</th>
                    <th className="px-4 py-3 text-right">Targets</th>
                    <th className="px-4 py-3 text-right">Findings</th>
                    <th className="px-4 py-3 text-right">Size (KB)</th>
                    <th className="px-4 py-3 text-right">Download</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {items.map((r) => (
                    <tr key={r.id} className="hover:bg-slate-50/60">
                      <td className="max-w-[18rem] truncate px-4 py-3 font-medium" title={r.file_name}>{r.file_name}</td>
                      <td className="px-4 py-3 tabular-nums">#{r.run_id}</td>
                      <td className="px-4 py-3 whitespace-nowrap">{formatDate(r.created_at)}</td>
                      <td className="px-4 py-3 text-right tabular-nums">{r.targets_count}</td>
                      <td className="px-4 py-3 text-right tabular-nums">{r.findings_count}</td>
                      <td className="px-4 py-3 text-right tabular-nums">{sizeKb(r.size_bytes)}</td>
                      <td className="px-4 py-3 text-right"><DownloadCell report={r} expired={!!expired[r.id]} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}

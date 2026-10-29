import { useEffect, useState, useCallback } from "react";
import { Archive, Pause, Play, Plus, Radar, Search, Upload } from "lucide-react";
import { Button, Card, EmptyState, ErrorText, Input, Modal, RiskBadge, TargetStatusBadge } from "../components/ui";
import { api, timeAgo, type BulkImportResult, type DomainGroup, type Target, type TargetPage } from "../lib/api";

const PAGE_SIZE = 25;

function AddTargetModal({ onClose, onDone }: { onClose: () => void; onDone: (r: BulkImportResult) => void }) {
  const [url, setUrl] = useState("");
  const [tags, setTags] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const result = await api.post<BulkImportResult>("/targets", {
        url,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      });
      if (result.created.length === 0) {
        setError(result.invalid[0]?.error ?? "Target already exists");
        return;
      }
      onDone(result);
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal title="Add target" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <label className="block space-y-1 text-sm">
          <span className="font-medium text-slate-700">URL</span>
          <Input required placeholder="https://api.example.com" value={url} onChange={(e) => setUrl(e.target.value)} autoFocus />
        </label>
        <label className="block space-y-1 text-sm">
          <span className="font-medium text-slate-700">Tags (comma separated)</span>
          <Input placeholder="prod, middleware" value={tags} onChange={(e) => setTags(e.target.value)} />
        </label>
        <ErrorText error={error} />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={saving || !url.trim()}>Add target</Button>
        </div>
      </form>
    </Modal>
  );
}

function BulkImportModal({ onClose, onDone }: { onClose: () => void; onDone: (r: BulkImportResult) => void }) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BulkImportResult | null>(null);
  const [saving, setSaving] = useState(false);
  const lineCount = text.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")).length;

  async function submit() {
    setSaving(true);
    setError(null);
    try {
      const r = await api.post<BulkImportResult>("/targets", { text });
      setResult(r);
      onDone(r);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal title="Bulk import URLs" onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-sm text-slate-500">
          One URL per line, or CSV as <code className="rounded bg-slate-100 px-1">url,tag1;tag2</code>. Lines starting with
          <code className="mx-1 rounded bg-slate-100 px-1">#</code> are ignored. Duplicates are skipped.
        </p>
        <textarea
          className="h-64 w-full rounded-lg border border-slate-300 p-3 font-mono text-sm focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200"
          placeholder={"https://kai.buckleconsult.com\nhttps://clinic.heykoala.ai,prod\n..."}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <ErrorText error={error} />
        {result && (
          <div className="rounded-lg bg-slate-50 p-3 text-sm">
            <div>Created <b>{result.created.length}</b> · Skipped duplicates <b>{result.skipped_duplicates.length}</b> · Invalid <b>{result.invalid.length}</b></div>
            {result.invalid.length > 0 && (
              <ul className="mt-2 max-h-28 list-disc overflow-auto pl-5 text-red-700">
                {result.invalid.map((i) => <li key={i.input}>{i.input}: {i.error}</li>)}
              </ul>
            )}
          </div>
        )}
        <div className="flex items-center justify-between">
          <span className="text-sm text-slate-500">{lineCount} line(s) detected</span>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={onClose}>{result ? "Close" : "Cancel"}</Button>
            {!result && <Button onClick={submit} disabled={saving || lineCount === 0}>Import {lineCount || ""}</Button>}
          </div>
        </div>
      </div>
    </Modal>
  );
}

export default function TargetsPage() {
  const [data, setData] = useState<TargetPage | null>(null);
  const [domains, setDomains] = useState<DomainGroup[]>([]);
  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [domain, setDomain] = useState<string>("");
  const [page, setPage] = useState(1);
  const [modal, setModal] = useState<"add" | "bulk" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (q) params.set("q", q);
    if (statusFilter) params.set("status", statusFilter);
    if (domain) params.set("domain", domain);
    try {
      setData(await api.get<TargetPage>(`/targets?${params}`));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [page, q, statusFilter, domain]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    api.get<DomainGroup[]>("/targets/domains").then(setDomains).catch(() => setDomains([]));
  }, []);

  useEffect(() => setPage(1), [q, statusFilter, domain]);

  async function mutate(fn: () => Promise<unknown>, success?: string) {
    try {
      await fn();
      setNotice(success ?? null);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function onImported(r: BulkImportResult) {
    setNotice(`Imported ${r.created.length}, skipped ${r.skipped_duplicates.length}, invalid ${r.invalid.length}.`);
    load();
    api.get<DomainGroup[]>("/targets/domains").then(setDomains).catch(() => undefined);
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Targets</h1>
          <p className="text-sm text-slate-500">Endpoints in the scan rotation. Only ACTIVE targets are scanned.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => setModal("bulk")}><Upload size={14} /> Bulk import</Button>
          <Button onClick={() => setModal("add")}><Plus size={14} /> Add target</Button>
        </div>
      </header>

      <ErrorText error={error} />
      {notice && <p className="rounded-md bg-emerald-50 px-3 py-2 text-sm text-emerald-800">{notice}</p>}

      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[220px] flex-1">
            <Search size={15} className="absolute left-3 top-2.5 text-slate-400" />
            <Input className="pl-9" placeholder="Search URL, host or tag" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select
            className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All statuses</option>
            <option value="ACTIVE">Active</option>
            <option value="PAUSED">Paused</option>
            <option value="ARCHIVED">Archived</option>
          </select>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            onClick={() => setDomain("")}
            className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset ${domain === "" ? "bg-slate-900 text-white ring-slate-900" : "text-slate-600 ring-slate-300 hover:bg-slate-50"}`}
          >
            All domains
          </button>
          {domains.map((d) => (
            <button
              key={d.domain_root}
              onClick={() => setDomain(d.domain_root)}
              className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset ${domain === d.domain_root ? "bg-slate-900 text-white ring-slate-900" : "text-slate-600 ring-slate-300 hover:bg-slate-50"}`}
            >
              *.{d.domain_root} <span className="opacity-60">{d.count}</span>
            </button>
          ))}
        </div>
      </Card>

      <Card className="overflow-hidden">
        {!data ? (
          <div className="p-6 text-sm text-slate-500">Loading…</div>
        ) : data.items.length === 0 ? (
          <EmptyState>No targets match. Add one or bulk import a list.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Tags</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Open findings</th>
                  <th className="px-4 py-3">Last scanned</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.items.map((t: Target) => (
                  <tr key={t.id} className="hover:bg-slate-50/60">
                    <td className="px-4 py-3">
                      <div className="font-medium">{t.host}</div>
                      <div className="text-xs text-slate-500">{t.url}</div>
                    </td>
                    <td className="px-4 py-3"><TargetStatusBadge status={t.status} /></td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {t.tags.map((tag) => (
                          <span key={tag} className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600">{tag}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3"><RiskBadge risk={t.risk} /></td>
                    <td className="px-4 py-3 tabular-nums">{t.vuln_counts.open}</td>
                    <td className="px-4 py-3 text-slate-500">
                      {timeAgo(t.last_scanned_at)}
                      {t.last_scan_status && <div className="text-xs text-slate-400">{t.last_scan_status.toLowerCase()}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" title="Scan this target now" disabled={t.status !== "ACTIVE"}
                          onClick={() => mutate(() => api.post("/scans/trigger", { scope: "target", target_id: t.id }), `Queued scan for ${t.host}`)}>
                          <Radar size={14} /> Scan
                        </Button>
                        {t.status === "ACTIVE" ? (
                          <Button variant="ghost" title="Pause scanning" onClick={() => mutate(() => api.patch(`/targets/${t.id}`, { status: "PAUSED" }))}>
                            <Pause size={14} />
                          </Button>
                        ) : t.status === "PAUSED" ? (
                          <Button variant="ghost" title="Resume scanning" onClick={() => mutate(() => api.patch(`/targets/${t.id}`, { status: "ACTIVE" }))}>
                            <Play size={14} />
                          </Button>
                        ) : null}
                        <Button variant="ghost" title="Archive (keeps history)" onClick={() => mutate(() => api.del(`/targets/${t.id}`), `Archived ${t.host}`)}>
                          <Archive size={14} />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-slate-600">
          <span>{data.total} targets</span>
          <div className="flex items-center gap-2">
            <Button variant="secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
            <span>Page {page} of {totalPages}</span>
            <Button variant="secondary" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
          </div>
        </div>
      )}

      {modal === "add" && <AddTargetModal onClose={() => setModal(null)} onDone={onImported} />}
      {modal === "bulk" && <BulkImportModal onClose={() => setModal(null)} onDone={onImported} />}
    </div>
  );
}

import { useEffect, useState, useCallback } from "react";
import { ExternalLink, Search, X } from "lucide-react";
import { Button, Card, EmptyState, ErrorText, Input, SeverityBadge, VulnStatusBadge } from "../components/ui";
import { api, formatDate, timeAgo, type VulnPage, type Vulnerability, type VulnStatus, type DomainGroup } from "../lib/api";

const PAGE_SIZE = 25;
const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const STATUS_OPTIONS: { value: VulnStatus; label: string }[] = [
  { value: "OPEN", label: "Open" },
  { value: "RESOLVED", label: "Resolved" },
  { value: "FALSE_POSITIVE", label: "False positive" },
  { value: "ACCEPTED_RISK", label: "Accepted risk" },
];

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="text-sm text-slate-800">{children}</div>
    </div>
  );
}

function Snippet({ title, body }: { title: string; body: string | null }) {
  if (!body) return null;
  return (
    <div>
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">{title}</div>
      <pre className="max-h-64 overflow-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100 whitespace-pre-wrap break-all">{body}</pre>
    </div>
  );
}

function FindingDrawer({ vuln, onClose, onChanged }: {
  vuln: Vulnerability;
  onClose: () => void;
  onChanged: (v: Vulnerability) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function setStatus(status: VulnStatus) {
    setSaving(true);
    setError(null);
    try {
      onChanged(await api.patch<Vulnerability>(`/vulnerabilities/${vuln.id}`, { status }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-900/30" onClick={onClose}>
      <aside
        role="dialog"
        aria-modal="true"
        className="flex h-full w-full max-w-2xl flex-col overflow-y-auto bg-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between border-b border-slate-200 p-5">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={vuln.severity} />
              <VulnStatusBadge status={vuln.status} />
              {vuln.cve_id && <span className="font-mono text-sm font-semibold">{vuln.cve_id}</span>}
            </div>
            <h2 className="text-lg font-semibold">{vuln.name}</h2>
            <p className="text-xs text-slate-500">template {vuln.template_id}{vuln.matcher_name ? ` · matcher ${vuln.matcher_name}` : ""}</p>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100" aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-6 p-5">
          <section className="grid grid-cols-2 gap-4">
            <Field label="CVSS">{vuln.cvss_score ?? "—"}</Field>
            <Field label="Missed scans">{vuln.missed_scans}</Field>
            <Field label="First seen">{formatDate(vuln.first_seen_at)}</Field>
            <Field label="Last seen">{formatDate(vuln.last_seen_at)} <span className="text-slate-400">({timeAgo(vuln.last_seen_at)})</span></Field>
            <Field label="Resolved">{formatDate(vuln.resolved_at)}</Field>
            <Field label="Domain">{vuln.domain_root}</Field>
          </section>

          <section>
            <Field label="Matched URL">
              <a href={vuln.matched_at} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 break-all text-blue-700 hover:underline">
                {vuln.matched_at} <ExternalLink size={12} />
              </a>
            </Field>
          </section>

          {vuln.description && (
            <section>
              <div className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Description</div>
              <p className="whitespace-pre-wrap text-sm text-slate-700">{vuln.description}</p>
            </section>
          )}

          <section>
            <div className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Recommended remediation</div>
            <p className="whitespace-pre-wrap text-sm text-slate-700">{vuln.remediation || "No remediation guidance published for this template."}</p>
          </section>

          <Snippet title="Request" body={vuln.request} />
          <Snippet title="Response excerpt" body={vuln.response} />
          <Snippet title="Reproduce (curl)" body={vuln.curl_command} />

          <section className="space-y-2 border-t border-slate-200 pt-5">
            <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Triage</div>
            <div className="flex flex-wrap gap-2">
              {STATUS_OPTIONS.map((opt) => (
                <Button
                  key={opt.value}
                  variant={vuln.status === opt.value ? "primary" : "secondary"}
                  disabled={saving}
                  onClick={() => setStatus(opt.value)}
                >
                  {opt.label}
                </Button>
              ))}
            </div>
            <ErrorText error={error} />
          </section>
        </div>
      </aside>
    </div>
  );
}

export default function VulnerabilitiesPage() {
  const [data, setData] = useState<VulnPage | null>(null);
  const [domains, setDomains] = useState<DomainGroup[]>([]);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState<string>("OPEN");
  const [domain, setDomain] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Vulnerability | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (q) params.set("q", q);
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (domain) params.set("domain", domain);
    try {
      setData(await api.get<VulnPage>(`/vulnerabilities?${params}`));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [page, q, severity, status, domain]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    api.get<DomainGroup[]>("/targets/domains").then(setDomains).catch(() => setDomains([]));
  }, []);

  useEffect(() => setPage(1), [q, severity, status, domain]);

  function onChanged(updated: Vulnerability) {
    setSelected(updated);
    setData((prev) =>
      prev ? { ...prev, items: prev.items.map((v) => (v.id === updated.id ? updated : v)) } : prev,
    );
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Vulnerabilities</h1>
        <p className="text-sm text-slate-500">Deduplicated findings across all targets. Open findings auto-resolve after two clean scans.</p>
      </header>

      <ErrorText error={error} />

      <Card className="p-4">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
          <div className="relative md:col-span-5">
            <Search size={15} className="absolute left-3 top-2.5 text-slate-400" />
            <Input className="pl-9" placeholder="Search CVE ID, template, name or hostname" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm md:col-span-2" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm md:col-span-2" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {STATUS_OPTIONS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
          <select className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm md:col-span-3" value={domain} onChange={(e) => setDomain(e.target.value)}>
            <option value="">All domains</option>
            {domains.map((d) => <option key={d.domain_root} value={d.domain_root}>*.{d.domain_root}</option>)}
          </select>
        </div>
      </Card>

      <Card className="overflow-hidden">
        {!data ? (
          <div className="p-6 text-sm text-slate-500">Loading…</div>
        ) : data.items.length === 0 ? (
          <EmptyState>No findings match these filters.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Finding</th>
                  <th className="px-4 py-3">Matched host</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">CVSS</th>
                  <th className="px-4 py-3">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.items.map((v) => (
                  <tr key={v.id} className="cursor-pointer hover:bg-slate-50" onClick={() => setSelected(v)}>
                    <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                    <td className="px-4 py-3">
                      <div className="font-medium">{v.cve_id ?? v.template_id}</div>
                      <div className="max-w-md truncate text-xs text-slate-500">{v.name}</div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-600">{v.target_url.replace(/^https?:\/\//, "")}</td>
                    <td className="px-4 py-3"><VulnStatusBadge status={v.status} /></td>
                    <td className="px-4 py-3 tabular-nums">{v.cvss_score ?? "—"}</td>
                    <td className="px-4 py-3 text-slate-500">{timeAgo(v.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-slate-600">
          <span>{data.total} findings</span>
          <div className="flex items-center gap-2">
            <Button variant="secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
            <span>Page {page} of {totalPages}</span>
            <Button variant="secondary" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
          </div>
        </div>
      )}

      {selected && <FindingDrawer vuln={selected} onClose={() => setSelected(null)} onChanged={onChanged} />}
    </div>
  );
}

import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { Activity, AlertTriangle, CheckCircle2, Globe, Loader2, Minus, Plus, RefreshCw, Play, Search, ShieldAlert, Shuffle, ShoppingCart, Square, TrendingUp, X } from "lucide-react";
import { Card, Button, ErrorText, Input, Modal } from "../components/ui";
import {
  api,
  cancelScanRun,
  fetchActiveTargets,
  getLiveScanStatus,
  parseTs,
  timeAgo,
  triggerTargetsScan,
  type ActiveTarget,
  DEFAULT_PRESET,
  PRESET_OPTIONS,
  type LiveScanStatus,
  type Reachability,
  type ScanPreset,
  type ScanRun,
  type Stats,
  type Target,
  type TargetPage,
} from "../lib/api";
import { addToCart, clearCart, removeFromCart, useCart } from "../lib/cart";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const BAR_COLOR: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const RUN_STATUS_STYLE: Record<string, string> = {
  QUEUED: "text-slate-600",
  RUNNING: "text-blue-700",
  COMPLETED: "text-emerald-700",
  FAILED: "text-red-600",
  CANCELLED: "text-amber-700",
};

const REACHABILITY_STYLE: Record<Reachability, string> = {
  REACHABLE: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  UNREACHABLE: "bg-red-50 text-red-700 ring-red-200",
  UNKNOWN: "bg-slate-100 text-slate-600 ring-slate-200",
};

const LIVE_STATE: Record<string, { label: string; cls: string }> = {
  IDLE: { label: "Idle", cls: "bg-slate-100 text-slate-700" },
  SCANNING: { label: "Scanning", cls: "bg-blue-100 text-blue-800" },
  UPDATING_TEMPLATES: { label: "Updating templates", cls: "bg-violet-100 text-violet-800" },
  OFFLINE: { label: "Offline", cls: "bg-red-100 text-red-800" },
};

const POLL_ACTIVE_MS = 2000;
const POLL_IDLE_MS = 15000;
const SAMPLE_SIZE = 5;

/** Label for a run's scan preset. Runs with no preset fall back to "Custom" (legacy cve_years) or "Default". */
function presetLabel(run: Pick<ScanRun, "preset" | "cve_years">): string {
  const option = PRESET_OPTIONS.find((o) => o.value === run.preset);
  if (option) return option.label;
  if (run.cve_years) return "Custom";
  return "Default";
}

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

function isRunActive(run: ScanRun | null | undefined): boolean {
  return run?.status === "QUEUED" || run?.status === "RUNNING";
}

/** HH:MM:SS, clamped at zero so a small clock skew never shows a negative time. */
function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(Math.floor(total / 3600))}:${pad(Math.floor((total % 3600) / 60))}:${pad(total % 60)}`;
}

/** mm:ss for a finished run's duration; em dash when the duration is not known. */
function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const total = Math.max(0, Math.floor(seconds));
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(Math.floor(total / 60))}:${pad(total % 60)}`;
}

/** Share of the run's targets already scanned, 0-100. */
function runProgressPercent(run: ScanRun): number {
  const total = run.targets_count;
  if (!total || total <= 0) return 0;
  return Math.min(100, Math.round(((run.targets_scanned ?? 0) / total) * 100));
}

/** Uniform random sample without repeats (partial Fisher-Yates). */
function pickRandom<T>(items: T[], n: number): T[] {
  const copy = items.slice();
  for (let i = 0; i < n; i++) {
    const j = i + Math.floor(Math.random() * (copy.length - i));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, n);
}

/** Ticks once per second. `offsetMs` is server clock minus client clock, so the result follows the server. */
function ElapsedTimer({ startedAt, offsetMs }: { startedAt: number; offsetMs: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <span className="font-mono text-2xl font-semibold tabular-nums">
      {formatElapsed(now + offsetMs - startedAt)}
    </span>
  );
}

/** Review panel for the scanner cart: edit the cart, pick a preset, and scan the cart as one run. */
function ScanCartModal({ onClose, onScanned }: { onClose: () => void; onScanned: (message: string) => void }) {
  const cart = useCart();
  const [preset, setPreset] = useState<ScanPreset>(DEFAULT_PRESET);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [q, setQ] = useState("");
  const [results, setResults] = useState<Target[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);

  // Debounced search of ACTIVE targets while the picker is open. Stale responses are ignored.
  useEffect(() => {
    if (!pickerOpen) return;
    let cancelled = false;
    const timer = setTimeout(async () => {
      setSearching(true);
      try {
        const page = await api.get<TargetPage>(`/targets?status=ACTIVE&q=${encodeURIComponent(q.trim())}&page_size=20`);
        if (!cancelled) {
          setResults(page.items);
          setSearchError(null);
        }
      } catch (e) {
        if (!cancelled) setSearchError((e as Error).message);
      } finally {
        if (!cancelled) setSearching(false);
      }
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [pickerOpen, q]);

  async function scanCart() {
    if (cart.length === 0) return;
    setScanning(true);
    setError(null);
    try {
      const run = await triggerTargetsScan(cart.map((item) => item.id), preset);
      clearCart();
      const label = PRESET_OPTIONS.find((o) => o.value === preset)?.label ?? preset;
      onScanned(`Queued run #${run.id} over ${cart.length} target${cart.length === 1 ? "" : "s"} (${label}).`);
      onClose();
    } catch (e) {
      // The cart is left unchanged so the user can adjust it and retry.
      setError((e as Error).message);
    } finally {
      setScanning(false);
    }
  }

  return (
    <Modal title="Scanner cart" onClose={onClose} wide>
      <div className="space-y-4">
        {cart.length === 0 ? (
          <p className="text-sm text-slate-500">The cart is empty. Use “Move to scanner cart” on the Targets page or add targets below.</p>
        ) : (
          <ul className="max-h-64 divide-y divide-slate-100 overflow-y-auto rounded-lg border border-slate-200">
            {cart.map((item) => (
              <li key={item.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium" title={item.url}>{item.url}</div>
                  <div className="truncate text-xs text-slate-500">{item.host}</div>
                </div>
                <div className="flex shrink-0 gap-1">
                  <Button variant="ghost" aria-label={`Remove ${item.host} from cart`} title="Remove from cart"
                    onClick={() => removeFromCart(item.id)}>
                    <Minus size={14} />
                  </Button>
                  <Button variant="ghost" aria-label="Add more targets" title="Add more targets"
                    onClick={() => setPickerOpen(true)}>
                    <Plus size={14} />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}

        {cart.length === 0 && !pickerOpen && (
          <Button variant="secondary" onClick={() => setPickerOpen(true)}><Plus size={14} /> Add targets</Button>
        )}

        {pickerOpen && (
          <div className="space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search size={15} className="absolute left-3 top-2.5 text-slate-400" />
                <Input className="pl-9" placeholder="Search ACTIVE targets by URL" value={q}
                  onChange={(e) => setQ(e.target.value)} autoFocus />
              </div>
              <Button variant="ghost" aria-label="Close picker" onClick={() => setPickerOpen(false)}><X size={14} /></Button>
            </div>
            <ErrorText error={searchError} />
            {!searchError && !searching && results.length === 0 && (
              <p className="text-sm text-slate-500">No ACTIVE targets match.</p>
            )}
            <ul className="max-h-56 divide-y divide-slate-200 overflow-y-auto">
              {results.map((t) => {
                const inCart = cart.some((item) => item.id === t.id);
                return (
                  <li key={t.id} className="flex items-center justify-between gap-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium" title={t.url}>{t.url}</div>
                      <div className="truncate text-xs text-slate-500">{t.host}</div>
                    </div>
                    <Button variant="secondary" className="shrink-0" disabled={inCart}
                      onClick={() => addToCart({ id: t.id, url: t.url, host: t.host })}>
                      {inCart ? "In cart" : <><Plus size={14} /> Add</>}
                    </Button>
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        <ErrorText error={error} />

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
          <label className="flex items-center gap-2 text-sm text-slate-600">
            <span className="whitespace-nowrap">Scan preset</span>
            <select
              className="max-w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm disabled:opacity-50"
              value={preset}
              onChange={(e) => setPreset(e.target.value as ScanPreset)}
              disabled={scanning}
              aria-label="Scan preset for cart scan"
            >
              {PRESET_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </label>
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" onClick={clearCart} disabled={cart.length === 0 || scanning}>Clear cart</Button>
            <Button onClick={scanCart} disabled={cart.length === 0 || scanning}>
              {scanning ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />} Scan cart
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function LiveScanPanel() {
  const [snap, setSnap] = useState<{ status: LiveScanStatus; offsetMs: number } | null>(null);
  const cart = useCart();
  const [cartOpen, setCartOpen] = useState(false);
  const [pollError, setPollError] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const [stopError, setStopError] = useState<string | null>(null);
  const [sampling, setSampling] = useState(false);
  const [sampleError, setSampleError] = useState<string | null>(null);
  const [sampleResult, setSampleResult] = useState<string | null>(null);
  const [preset, setPreset] = useState<ScanPreset>(DEFAULT_PRESET);

  const load = useCallback(async () => {
    try {
      const received = Date.now();
      const status = await getLiveScanStatus();
      const serverTime = parseTs(status.server_time);
      setSnap({ status, offsetMs: serverTime ? serverTime.getTime() - received : 0 });
      setPollError(null);
    } catch (e) {
      setPollError((e as Error).message);
    }
  }, []);

  const run = snap?.status.current_run ?? null;
  const active = isRunActive(run);

  // Poll every 2s while a run is queued or running, otherwise at the slower idle interval.
  useEffect(() => {
    load();
    const id = setInterval(load, active ? POLL_ACTIVE_MS : POLL_IDLE_MS);
    return () => clearInterval(id);
  }, [load, active]);

  async function stop() {
    if (!run) return;
    setStopping(true);
    setStopError(null);
    try {
      await cancelScanRun(run.id);
    } catch (e) {
      setStopError((e as Error).message);
    } finally {
      setStopping(false);
      load();
    }
  }

  async function scanRandom() {
    setSampling(true);
    setSampleError(null);
    setSampleResult(null);
    try {
      const targets = await fetchActiveTargets();
      if (targets.length === 0) throw new Error("No active targets to scan.");
      const picked = pickRandom(targets, Math.min(SAMPLE_SIZE, targets.length));
      const queued = await triggerTargetsScan(picked.map((t) => t.id), preset);
      const label = PRESET_OPTIONS.find((o) => o.value === preset)?.label ?? preset;
      setSampleResult(`Queued run #${queued.id} over ${picked.length} random target${picked.length === 1 ? "" : "s"} (${label}).`);
      load();
    } catch (e) {
      setSampleError((e as Error).message);
    } finally {
      setSampling(false);
    }
  }

  if (!snap) {
    return (
      <Card className="p-5">
        <h2 className="text-sm font-semibold">Live scan</h2>
        <ErrorText error={pollError} />
        {!pollError && <p className="mt-2 text-sm text-slate-500">Loading scan status…</p>}
      </Card>
    );
  }

  const { status, offsetMs } = snap;
  const badge = LIVE_STATE[status.state] ?? LIVE_STATE.IDLE;
  const cancelRequested = run?.cancel_requested === true;
  const canStop = active && !stopping && !cancelRequested;
  const showTimer = run?.status === "RUNNING" && run.started_at !== null;
  const startedAt = parseTs(run?.started_at)?.getTime();
  const targets: ActiveTarget[] = status.active_targets;

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-semibold">Live scan</h2>
        <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${badge.cls}`}>
          {(status.state === "SCANNING" || status.state === "UPDATING_TEMPLATES") && <Loader2 size={12} className="animate-spin" />}
          {badge.label}
        </span>
      </div>

      <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          {run ? (
            <>
              <div className="text-sm">
                <span className="text-slate-500">Run</span>{" "}
                <span className="font-medium tabular-nums">#{run.id}</span>{" "}
                <span className={`font-medium ${RUN_STATUS_STYLE[run.status] ?? "text-slate-600"}`}>{run.status}</span>
                {cancelRequested && <span className="ml-2 text-xs text-amber-700">cancel requested</span>}
                <span className="ml-2 text-xs text-slate-500">{presetLabel(run)}</span>
              </div>
              {showTimer && startedAt !== undefined && (
                <div className="mt-1 text-xs text-slate-500">
                  Elapsed <ElapsedTimer key={run.id} startedAt={startedAt} offsetMs={offsetMs} />
                </div>
              )}
            </>
          ) : (
            <div className="text-sm text-slate-500">No run in progress.</div>
          )}
        </div>
        <Button variant="danger" onClick={stop} disabled={!canStop} className="px-4 py-2 text-base">
          {stopping || cancelRequested ? (
            <>
              <Loader2 size={14} className="animate-spin" /> Stopping…
            </>
          ) : (
            <>
              <Square size={14} /> Stop scan
            </>
          )}
        </Button>
      </div>
      <ErrorText error={stopError} />

      {run && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-xs text-slate-500">
            <span className="tabular-nums">
              {run.targets_scanned ?? 0} of {run.targets_count} targets
              {(run.chunks_total ?? 0) > 0 && <> · chunk {run.chunks_done ?? 0} of {run.chunks_total}</>}
            </span>
            <span className="font-medium tabular-nums text-slate-700">{runProgressPercent(run)}%</span>
          </div>
          <div
            className="mt-1.5 h-2.5 overflow-hidden rounded-full bg-slate-100"
            role="progressbar"
            aria-label="Scan progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={runProgressPercent(run)}
          >
            <div className="h-full rounded-full bg-blue-600 transition-all duration-500" style={{ width: `${runProgressPercent(run)}%` }} />
          </div>
          <div className="mt-1.5 text-xs text-slate-500">{run.unreachable_count ?? 0} unreachable skipped</div>
        </div>
      )}

      <div className="mt-4 grid grid-cols-3 gap-3">
        {[
          { label: "Targets", value: run?.targets_count ?? 0 },
          { label: "Unreachable", value: run?.unreachable_count ?? 0 },
          { label: "Live findings", value: status.live_findings ?? "—" },
        ].map((c) => (
          <div key={c.label} className="rounded-lg bg-slate-50 px-3 py-2">
            <div className="text-xs text-slate-500">{c.label}</div>
            <div className="text-xl font-semibold tabular-nums">{c.value}</div>
          </div>
        ))}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button variant="secondary" onClick={scanRandom} disabled={active || sampling}>
          {sampling ? <Loader2 size={14} className="animate-spin" /> : <Shuffle size={14} />}
          Scan {SAMPLE_SIZE} random targets
        </Button>
        <Button variant="secondary" onClick={() => setCartOpen(true)}>
          <ShoppingCart size={14} /> Cart ({cart.length})
        </Button>
        <label className="flex items-center gap-2 text-sm text-slate-600">
          <span className="whitespace-nowrap">Scan preset</span>
          <select
            className="max-w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm disabled:opacity-50"
            value={preset}
            onChange={(e) => setPreset(e.target.value as ScanPreset)}
            disabled={active || sampling}
            aria-label="Scan preset for random scan"
          >
            {PRESET_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </label>
        {sampleResult && <span className="text-sm text-emerald-700">{sampleResult}</span>}
      </div>
      <ErrorText error={sampleError} />
      <ErrorText error={pollError} />

      {cartOpen && (
        <ScanCartModal
          onClose={() => setCartOpen(false)}
          onScanned={(message) => {
            setSampleError(null);
            setSampleResult(message);
            load();
          }}
        />
      )}

      <div className="mt-5">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Actively scanning</h3>
        {targets.length === 0 ? (
          <p className="text-sm text-slate-500">No active scan.</p>
        ) : (
          <ul className="max-h-64 divide-y divide-slate-100 overflow-y-auto rounded-lg border border-slate-100">
            {targets.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium" title={t.url}>{t.url}</div>
                  <div className="truncate text-xs text-slate-500">{t.host}</div>
                </div>
                <span className={`inline-flex shrink-0 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${REACHABILITY_STYLE[t.reachability] ?? REACHABILITY_STYLE.UNKNOWN}`}>
                  {t.reachability.toLowerCase()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}

export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cleanCount, setCleanCount] = useState<number | null>(null);

  // Active targets whose last scan was clean. Only the total is used, so page_size=1 keeps it cheap.
  useEffect(() => {
    let cancelled = false;
    const loadClean = () =>
      api
        .get<TargetPage>("/targets?status=ACTIVE&result=CLEAN&page_size=1")
        .then((r) => {
          if (!cancelled) setCleanCount(r.total);
        })
        .catch(() => undefined);
    loadClean();
    const id = setInterval(loadClean, 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

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

      <LiveScanPanel />

      {stats.spike && (
        <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <AlertTriangle size={16} />
          New-findings spike: {stats.new_findings_last_24h} in the last 24h vs {stats.new_findings_previous_24h} before.
        </div>
      )}

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard label="Monitored endpoints" value={stats.total_monitored_endpoints}
          icon={Globe} hint={`${stats.active_targets} active · ${stats.paused_targets} paused`} />
        <StatCard label="Active critical CVEs" value={stats.active_critical} icon={ShieldAlert}
          tone="text-sev-critical" hint="open findings" />
        <StatCard label="Active high CVEs" value={stats.active_high} icon={ShieldAlert}
          tone="text-sev-high" hint={stats.mttr_hours !== null ? `MTTR ${stats.mttr_hours}h (90d)` : "MTTR: no data yet"} />
        <StatCard label="Scans run (24h)" value={stats.scans_run_last_24h} icon={Activity}
          hint={`${stats.new_findings_last_24h} new findings today`} />
        <Link to="/targets?result=CLEAN" className="block rounded-xl focus:outline-none focus:ring-2 focus:ring-slate-300"
          title="Show clean targets">
          <StatCard label="Clean endpoints" value={cleanCount ?? "—"} icon={CheckCircle2} tone="text-emerald-600"
            hint="active, last scan clean" />
        </Link>
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
                  <th className="py-2 pr-4 text-right">Duration</th>
                  <th className="py-2 pr-4">Started</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {stats.scanner.recent_runs.map((r) => (
                  <tr key={r.id}>
                    <td className="py-2 pr-4 tabular-nums">#{r.id}</td>
                    <td className="py-2 pr-4">
                      {r.scope === "TARGET" ? `target ${r.target_id}` : r.scope === "TARGETS" ? "selected targets" : "all active"}
                      <div className="text-xs text-slate-500">{presetLabel(r)}</div>
                    </td>
                    <td className="py-2 pr-4">
                      <span className={RUN_STATUS_STYLE[r.status] ?? "text-slate-600"}>{r.status}</span>
                      {r.error && <div className="max-w-xs truncate text-xs text-red-500" title={r.error}>{r.error}</div>}
                    </td>
                    <td className="py-2 pr-4 text-right tabular-nums">{r.targets_count}</td>
                    <td className="py-2 pr-4 text-right tabular-nums">{r.findings_count}</td>
                    <td className="py-2 pr-4 text-right tabular-nums">{r.new_findings}</td>
                    <td className="py-2 pr-4 text-right font-mono tabular-nums text-slate-600">{formatDuration(r.duration_seconds)}</td>
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

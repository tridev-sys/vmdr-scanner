import clsx from "clsx";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import type { RiskLevel, Severity, TargetStatus, VulnStatus } from "../lib/api";

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("rounded-xl border border-slate-200 bg-white shadow-sm", className)}>{children}</div>;
}

const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-red-100 text-red-800 ring-red-200",
  high: "bg-orange-100 text-orange-800 ring-orange-200",
  medium: "bg-yellow-100 text-yellow-800 ring-yellow-200",
  low: "bg-blue-100 text-blue-800 ring-blue-200",
  info: "bg-slate-100 text-slate-700 ring-slate-200",
  unknown: "bg-slate-100 text-slate-500 ring-slate-200",
};

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const key = (severity in SEV_STYLE ? severity : "unknown") as Severity;
  return (
    <span className={clsx("inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ring-inset", SEV_STYLE[key])}>
      {key}
    </span>
  );
}

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  if (risk === "none") return <span className="text-xs text-slate-400">no open findings</span>;
  return <SeverityBadge severity={risk} />;
}

const TARGET_STYLE: Record<TargetStatus, string> = {
  ACTIVE: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  PAUSED: "bg-amber-50 text-amber-700 ring-amber-200",
  ARCHIVED: "bg-slate-100 text-slate-600 ring-slate-200",
};

export function TargetStatusBadge({ status }: { status: TargetStatus }) {
  return (
    <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset", TARGET_STYLE[status])}>
      {status}
    </span>
  );
}

const VULN_STYLE: Record<VulnStatus, string> = {
  OPEN: "bg-red-50 text-red-700 ring-red-200",
  RESOLVED: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  FALSE_POSITIVE: "bg-slate-100 text-slate-600 ring-slate-200",
  ACCEPTED_RISK: "bg-violet-50 text-violet-700 ring-violet-200",
};

export function VulnStatusBadge({ status }: { status: VulnStatus }) {
  return (
    <span className={clsx("inline-flex rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset", VULN_STYLE[status])}>
      {status.replace("_", " ")}
    </span>
  );
}

export function Button({
  children,
  variant = "primary",
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger" }) {
  const styles = {
    primary: "bg-slate-900 text-white hover:bg-slate-700",
    secondary: "bg-white text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50",
    ghost: "text-slate-600 hover:bg-slate-100",
    danger: "bg-red-600 text-white hover:bg-red-500",
  }[variant];
  return (
    <button
      {...props}
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50",
        styles,
        className,
      )}
    >
      {children}
    </button>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={clsx(
        "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm placeholder:text-slate-400 focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200",
        props.className,
      )}
    />
  );
}

export function Modal({
  title,
  onClose,
  children,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        className={clsx("w-full rounded-xl bg-white p-6 shadow-xl", wide ? "max-w-2xl" : "max-w-md")}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600" aria-label="Close">
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function ErrorText({ error }: { error: string | null }) {
  if (!error) return null;
  return <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="py-12 text-center text-sm text-slate-500">{children}</div>;
}

import clsx from "clsx";
import { KeyRound, LayoutDashboard, Bug, Globe, ShieldCheck, FileText } from "lucide-react";
import { NavLink, Route, Routes } from "react-router-dom";
import { getApiKey, setApiKey } from "./lib/api";
import { useState } from "react";
import OverviewPage from "./pages/Overview";
import TargetsPage from "./pages/Targets";
import VulnerabilitiesPage from "./pages/Vulnerabilities";
import ReportsPage from "./pages/Reports";
import { Input } from "./components/ui";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/targets", label: "Targets", icon: Globe, end: false },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug, end: false },
  { to: "/reports", label: "Reports", icon: FileText, end: false },
];

function ApiKeyBox() {
  const [value, setValue] = useState(getApiKey());
  const [saved, setSaved] = useState(false);
  return (
    <div className="space-y-2">
      <label className="flex items-center gap-1.5 text-xs font-medium text-slate-500">
        <KeyRound size={13} /> API key (write actions)
      </label>
      <Input
        type="password"
        placeholder="optional"
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          setSaved(false);
        }}
        onBlur={() => {
          setApiKey(value.trim());
          setSaved(true);
        }}
      />
      {saved && <p className="text-xs text-slate-400">Saved in this browser.</p>}
    </div>
  );
}

export default function App() {
  return (
    <div className="min-h-screen md:flex">
      <aside className="border-b border-slate-200 bg-white md:fixed md:inset-y-0 md:w-60 md:border-b-0 md:border-r">
        <div className="flex items-center gap-2 px-5 py-5">
          <ShieldCheck className="text-slate-900" size={22} />
          <span className="text-base font-semibold tracking-tight">VMDR</span>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-col md:pb-0">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                clsx(
                  "flex items-center gap-2.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-medium transition",
                  isActive ? "bg-slate-900 text-white" : "text-slate-600 hover:bg-slate-100",
                )
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="hidden px-5 pt-6 md:absolute md:inset-x-0 md:bottom-0 md:block md:p-5">
          <ApiKeyBox />
        </div>
      </aside>

      <main className="flex-1 px-4 py-6 md:ml-60 md:px-8 md:py-8">
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/reports" element={<ReportsPage />} />
        </Routes>
      </main>
    </div>
  );
}

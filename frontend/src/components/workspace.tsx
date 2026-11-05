"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronRight,
  CircleHelp,
  Clipboard,
  FileSearch,
  FileText,
  Fingerprint,
  FlaskConical,
  Globe,
  LayoutDashboard,
  LoaderCircle,
  Mail,
  Menu,
  Network,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Target,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Button } from "./ui/button";
import { api, date, defang, download } from "@/lib/api";
import type {
  Analysis,
  CaseSummary,
  Dashboard,
  IOC,
  Investigation,
  Intelligence,
  Mapping,
  Preferences,
  Sample,
  Settings,
  Technique,
} from "@/lib/types";

const nav = [
  { path: "/", label: "Overview", icon: LayoutDashboard },
  { path: "/new", label: "New investigation", icon: Plus },
  { path: "/investigations", label: "Investigation history", icon: FileSearch },
  { path: "/forensics", label: "Email forensics", icon: Mail },
  { path: "/iocs", label: "IOC intelligence", icon: Fingerprint },
  { path: "/mitre", label: "MITRE ATT&CK", icon: Network },
  { path: "/reports", label: "Incident reports", icon: FileText },
  { path: "/settings", label: "Settings", icon: Settings2 },
];
const colors: Record<string, string> = {
  critical: "#f07178",
  high: "#f5a970",
  medium: "#e5c66b",
  low: "#5ec9a5",
};
type Notify = (message: string) => void;

function useResource<T>(path: string) {
  const [resource, setResource] = useState<{ path: string; value: T } | null>(
      null,
    ),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  const sequence = useRef(0);
  const refresh = useCallback(async () => {
    const request = ++sequence.current;
    setLoading(true);
    setError("");
    try {
      const value = await api<T>(path);
      if (request === sequence.current) setResource({ path, value });
    } catch (e) {
      if (request === sequence.current) setError((e as Error).message);
    } finally {
      if (request === sequence.current) setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    void refresh();
    return () => {
      sequence.current++;
    };
  }, [refresh]);
  return {
    data: resource?.path === path ? resource.value : null,
    error,
    loading,
    refresh,
  };
}

function useModalKeyboard(open: boolean, onClose: () => void) {
  const close = useRef(onClose);
  const opener = useRef<HTMLElement | null>(null);
  close.current = onClose;
  useEffect(() => {
    if (!open) return;
    const previous =
      opener.current || (document.activeElement as HTMLElement | null);
    function keyboard(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        close.current();
      }
      if (event.key !== "Tab") return;
      const elements = [
        ...document.querySelectorAll<HTMLElement>(
          '[role="dialog"] button:not(:disabled), [role="dialog"] input:not(:disabled), [role="dialog"] select, [role="dialog"] a[href]',
        ),
      ].filter((e) => e.getClientRects().length);
      const first = elements[0],
        last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      }
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    }
    document.addEventListener("keydown", keyboard);
    return () => {
      document.removeEventListener("keydown", keyboard);
      previous?.focus();
    };
  }, [open]);
  return (element: HTMLElement) => {
    opener.current = element;
  };
}
function Load({ error, retry }: { error: string; retry: () => void }) {
  return error ? (
    <div className="empty error" role="alert">
      <ShieldAlert />
      <h2>Unable to load workspace data</h2>
      <p>{error}</p>
      <Button onClick={retry}>Try again</Button>
    </div>
  ) : (
    <div className="skeleton" aria-label="Loading">
      <div />
      <div />
      <div />
    </div>
  );
}
function Badge({ value }: { value: string }) {
  return (
    <span className={`badge ${value.replace(/\s/g, "-")}`}>
      <span />
      {value}
    </span>
  );
}
function Empty({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="empty">
      <FileSearch size={30} />
      <h2>{title}</h2>
      <p>{children}</p>
    </div>
  );
}
function PageHead({
  eyebrow = "INVESTIGATION WORKSPACE",
  title,
  description,
  children,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="head-actions">{children}</div>
    </div>
  );
}
function Panel({
  title,
  subtitle,
  children,
  action,
  className = "",
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="notice">
      <Shield size={16} />
      <span>{children}</span>
    </div>
  );
}

export default function Workspace() {
  const path = usePathname(),
    [open, setOpen] = useState(false),
    [toast, setToast] = useState("");
  const notify = useCallback((message: string) => setToast(message), []);
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(""), 5000);
      return () => clearTimeout(timer);
    }
  }, [toast]);
  const active = nav.find((n) =>
    n.path === "/" ? path === "/" : path.startsWith(n.path),
  );
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className={`sidebar ${open ? "is-open" : ""}`}>
        <Link href="/" className="brand" onClick={() => setOpen(false)}>
          <div className="brand-mark">
            <ShieldCheck size={25} />
          </div>
          <div>
            PhishScope<small>SECURITY OPERATIONS</small>
          </div>
        </Link>
        <div className="workspace-label">
          <span className="workspace-avatar">PS</span>
          <div>
            Investigation workspace<small>Local environment</small>
          </div>
          <span className="online-dot" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {nav.map((item, i) => (
            <Link
              key={item.path}
              href={item.path}
              onClick={() => setOpen(false)}
              className={`${active?.path === item.path ? "active" : ""} ${i === 7 ? "settings-nav" : ""}`}
            >
              <item.icon size={18} />
              {item.label}
              {active?.path === item.path && (
                <span className="nav-active-dot" />
              )}
            </Link>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <ShieldCheck size={20} />
          <strong>Evidence stays local</strong>
          <p>External intelligence runs only when you request it.</p>
          <Link href="/settings">
            View configuration <ArrowRight size={13} />
          </Link>
        </div>
        <div className="analyst">
          <div className="avatar">SA</div>
          <div>
            SOC Analyst<small>Local analyst workspace</small>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              aria-label="Toggle navigation"
              onClick={() => setOpen(!open)}
            >
              <Menu size={20} />
            </button>
            <Shield size={16} />
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{active?.label || "Investigation detail"}</strong>
          </div>
          <div className="topbar-right">
            <span className="local-status">
              <span className="online-dot" />
              Local analysis enabled
            </span>
            <Link
              href="/settings"
              aria-label="Help and configuration"
              className="icon-button"
            >
              <CircleHelp size={18} />
            </Link>
            <div className="avatar small">SA</div>
          </div>
        </header>
        <main id="main">
          {path === "/" ? (
            <Overview notify={notify} />
          ) : path === "/new" ? (
            <NewInvestigation notify={notify} />
          ) : path === "/investigations" ? (
            <History notify={notify} />
          ) : path.startsWith("/investigations/") ? (
            <CaseDetail id={path.split("/")[2]} notify={notify} />
          ) : path === "/forensics" ? (
            <CasePicker mode="forensics" />
          ) : path === "/iocs" ? (
            <IOCPage notify={notify} />
          ) : path === "/mitre" ? (
            <MitreExplorer />
          ) : path === "/reports" ? (
            <CasePicker mode="reports" />
          ) : path === "/settings" ? (
            <SettingsPage notify={notify} />
          ) : (
            <Empty title="Page not found">
              <Link href="/">Return to overview</Link>
            </Empty>
          )}
        </main>
        <footer className="app-footer">
          <span>
            PhishScope <span className="muted">/</span> Evidence-led incident
            investigation
          </span>
          <span>v1.0.0 · Local workspace</span>
        </footer>
      </div>
      {toast && (
        <div className="toast" role="status">
          <Check size={16} />
          {toast}
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}

function CaseTable({ cases, tab }: { cases: CaseSummary[]; tab?: string }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Investigation</th>
            <th>Severity</th>
            <th>Risk score</th>
            <th>Indicators</th>
            <th>Created</th>
            <th>
              <span className="sr-only">Open</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {cases.map((c) => (
            <tr key={c.id}>
              <td>
                <Link
                  className="case-name"
                  href={`/investigations/${c.id}${tab ? `?tab=${tab}` : ""}`}
                >
                  <span className="case-icon">
                    <Mail size={17} />
                  </span>
                  <span>
                    <strong>{c.name}</strong>
                    <small>
                      {c.simulation ? "SIMULATION · " : ""}
                      {c.id.slice(0, 8).toUpperCase()}
                    </small>
                  </span>
                </Link>
              </td>
              <td>
                <Badge value={c.risk.severity} />
              </td>
              <td>
                <div className="score-inline">
                  <span>
                    {c.risk.score}
                    <small>/100</small>
                  </span>
                  <div className="score-track">
                    <i
                      style={{
                        width: `${c.risk.score}%`,
                        background: colors[c.risk.severity],
                      }}
                    />
                  </div>
                </div>
              </td>
              <td className="mono">{c.ioc_count}</td>
              <td className="muted nowrap">{date(c.created_at)}</td>
              <td>
                <Link
                  href={`/investigations/${c.id}${tab ? `?tab=${tab}` : ""}`}
                  aria-label={`Open ${c.name}`}
                  className="icon-button"
                >
                  <ArrowRight size={17} />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Overview({ notify }: { notify: Notify }) {
  const { data: d, error, refresh } = useResource<Dashboard>("/dashboard");
  const [busy, setBusy] = useState(false);
  async function demo() {
    setBusy(true);
    try {
      await api("/demo", { method: "POST" });
      notify("Four labelled simulation cases are ready.");
      await refresh();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!d) return <Load error={error} retry={refresh} />;
  const distribution = Object.entries(d.severities).map(([name, value]) => ({
    name,
    value,
  }));
  return (
    <>
      <PageHead
        eyebrow="SECURITY OPERATIONS CENTER"
        title="Investigation overview"
        description="A clear view of your phishing investigations and emerging evidence."
      >
        <Button variant="outline" onClick={refresh}>
          <RefreshCw size={15} />
          Refresh
        </Button>
        <Button asChild>
          <Link href="/new">
            <Plus size={17} />
            New investigation
          </Link>
        </Button>
      </PageHead>
      <div className="overview-strip">
        <span>
          <span className="online-dot" />
          Workspace operational
        </span>
        <span>All metrics from stored investigations</span>
        <span className="strip-right">
          <Shield size={13} />
          Offline-first analysis
        </span>
      </div>
      {!d.total && (
        <div className="welcome">
          <div>
            <div className="eyebrow">YOUR WORKSPACE IS READY</div>
            <h2>Start with the evidence.</h2>
            <p>
              Submit a suspicious email, or explore four safe synthetic
              investigations.
            </p>
          </div>
          <Button variant="outline" disabled={busy} onClick={demo}>
            <FlaskConical size={17} />
            {busy ? "Analyzing samples…" : "Load demonstration cases"}
          </Button>
        </div>
      )}
      <div className="metrics">
        {[
          {
            label: "Total investigations",
            value: d.total,
            icon: FileSearch,
            meta: `${d.completed} completed · ${d.pending} pending`,
          },
          {
            label: "Critical incidents",
            value: d.severities.critical,
            icon: ShieldAlert,
            meta: "Risk score 75–100",
            tone: "critical",
          },
          {
            label: "High-risk incidents",
            value: d.severities.high,
            icon: Target,
            meta: "Risk score 50–74",
            tone: "high",
          },
          {
            label: "Externally flagged indicators",
            value: d.confirmed_malicious,
            icon: Fingerprint,
            meta: "Provider-reported malicious",
            tone: "low",
          },
        ].map((m) => (
          <section className={`metric ${m.tone || ""}`} key={m.label}>
            <div className="metric-label">
              {m.label}
              <m.icon size={18} />
            </div>
            <div className="metric-number">
              {m.value.toString().padStart(2, "0")}
            </div>
            <p>
              <span className={`metric-dot ${m.tone || ""}`} />
              {m.meta}
            </p>
          </section>
        ))}
      </div>
      <div className="chart-grid">
        <Panel
          title="Investigation activity"
          subtitle="Email submissions over the last 7 days"
          action={
            <span className="mini-label">
              <span className="legend-dot" />
              Investigations
            </span>
          }
        >
          <div className="activity-chart">
            <ResponsiveContainer width="100%" height={225}>
              <AreaChart
                data={d.timeline}
                margin={{ top: 20, right: 20, left: -25, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="area" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6daafa" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="#6daafa" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  vertical={false}
                  stroke="#243041"
                  strokeDasharray="3 4"
                />
                <XAxis
                  dataKey="date"
                  tickFormatter={(v) =>
                    new Date(v + "T12:00:00").toLocaleDateString(undefined, {
                      month: "short",
                      day: "numeric",
                    })
                  }
                  tick={{ fill: "#96a4b7", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: "#96a4b7", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#172132",
                    border: "1px solid #344155",
                    borderRadius: 6,
                    color: "#edf3fc",
                  }}
                />
                <Area
                  isAnimationActive={false}
                  dataKey="investigations"
                  type="monotone"
                  stroke="#75aaff"
                  strokeWidth={2}
                  fill="url(#area)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel
          title="Severity distribution"
          subtitle="Application-defined risk assessment"
        >
          <div className="severity-chart">
            <div className="donut">
              <ResponsiveContainer width="100%" height={170}>
                <PieChart>
                  <Pie
                    isAnimationActive={false}
                    data={
                      d.total ? distribution : [{ name: "empty", value: 1 }]
                    }
                    dataKey="value"
                    innerRadius={55}
                    outerRadius={72}
                    paddingAngle={d.total ? 4 : 0}
                    stroke="none"
                  >
                    {(d.total ? distribution : [{ name: "empty" }]).map((s) => (
                      <Cell key={s.name} fill={colors[s.name] || "#243041"} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center">
                <strong>{d.total}</strong>
                <span>TOTAL CASES</span>
              </div>
            </div>
            <div className="severity-legend">
              {distribution.map((s) => (
                <div key={s.name}>
                  <span>
                    <i style={{ background: colors[s.name] }} />
                    {s.name}
                  </span>
                  <strong>{s.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>
      <Panel
        title="Recent investigations"
        subtitle="Latest cases in your workspace"
        action={
          <Link className="text-link" href="/investigations">
            View all investigations <ArrowRight size={14} />
          </Link>
        }
      >
        {d.recent.length ? (
          <CaseTable cases={d.recent} />
        ) : (
          <Empty title="No investigations yet">
            Your cases will appear here after you submit an email.
          </Empty>
        )}
      </Panel>
      <div className="bottom-grid">
        <Panel
          title="Indicator categories"
          subtitle="Extracted from the latest analysis of each case"
        >
          <div className="category-list">
            {Object.entries(d.ioc_categories)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 6)
              .map(([key, value]) => (
                <div key={key}>
                  <span>
                    <Fingerprint size={15} />
                    {key.toUpperCase()}
                  </span>
                  <div className="category-track">
                    <i
                      style={{
                        width: `${(value / Math.max(...Object.values(d.ioc_categories))) * 100}%`,
                      }}
                    />
                  </div>
                  <strong>{value}</strong>
                </div>
              ))}
            {!Object.keys(d.ioc_categories).length && (
              <p className="muted">No indicators extracted yet.</p>
            )}
          </div>
        </Panel>
        <Panel
          title="Assessment context"
          subtitle="Know what the evidence can establish"
        >
          <div className="context-row">
            <ShieldCheck />
            <div>
              <strong>Evidence before conclusions</strong>
              <p>
                Risk reflects message characteristics. It does not establish a
                click, execution, or account compromise.
              </p>
            </div>
          </div>
          <div className="context-row">
            <Globe />
            <div>
              <strong>External reputation is opt-in</strong>
              <p>
                No indicator or email content is submitted automatically.
                Unknown reputation stays unverified.
              </p>
            </div>
          </div>
        </Panel>
      </div>
    </>
  );
}

function NewInvestigation({ notify }: { notify: Notify }) {
  const router = useRouter(),
    [mode, setMode] = useState("paste"),
    [name, setName] = useState(""),
    [raw, setRaw] = useState(""),
    [file, setFile] = useState<File | null>(null),
    [sample, setSample] = useState("account"),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const { data: samples } = useResource<Sample[]>("/samples");
  useEffect(() => {
    api<Settings>("/settings")
      .then((s) => setMode(s.preferences.default_input))
      .catch(() => {});
  }, []);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      let c: Investigation;
      if (mode === "sample") {
        c = await api(`/samples/${sample}`, { method: "POST" });
      } else if (mode === "upload") {
        if (!file) throw new Error("Select an .eml or .txt file.");
        if (file.size > 5 * 1024 * 1024)
          throw new Error("The maximum file size is 5 MiB.");
        const data = new FormData();
        data.append("file", file);
        c = await api("/upload", { method: "POST", body: data });
      } else {
        c = await api("/investigations", {
          method: "POST",
          body: JSON.stringify({
            name: name || "Email investigation",
            raw_email: raw,
          }),
        });
      }
      notify("Investigation analyzed and saved.");
      router.push(`/investigations/${c.id}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHead
        title="New investigation"
        description="Bring in a suspicious email. Build an evidence-backed assessment."
      />
      <div className="submission-grid">
        <form className="panel submission" onSubmit={submit}>
          <div className="tabs" role="tablist" aria-label="Email input method">
            {[
              { id: "paste", label: "Paste raw email", icon: Clipboard },
              { id: "upload", label: "Upload email", icon: Upload },
              { id: "sample", label: "Demonstration", icon: FlaskConical },
            ].map((m) => (
              <button
                type="button"
                key={m.id}
                role="tab"
                aria-selected={mode === m.id}
                className={mode === m.id ? "selected" : ""}
                onClick={() => setMode(m.id)}
              >
                <m.icon size={16} />
                {m.label}
              </button>
            ))}
          </div>
          <div className="form-body">
            {mode === "paste" ? (
              <>
                <label htmlFor="case-name">Investigation name</label>
                <input
                  id="case-name"
                  maxLength={200}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Suspicious account verification"
                />
                <label htmlFor="raw-email">
                  Raw email evidence <span>Required</span>
                </label>
                <textarea
                  id="raw-email"
                  className="email-editor"
                  rows={16}
                  required
                  value={raw}
                  onChange={(e) => setRaw(e.target.value)}
                  placeholder={
                    "From: sender@example.test\nTo: analyst@company.example\nSubject: Suspicious message\n\nPaste complete headers and email body here…"
                  }
                />
                <p className="field-help">
                  Include the From and Subject headers. Maximum 5 MiB.
                </p>
              </>
            ) : mode === "upload" ? (
              <>
                <h2>Upload original email</h2>
                <p className="muted">
                  Preserve complete headers by exporting the original message
                  from your email client.
                </p>
                <label className="upload-zone" htmlFor="email-file">
                  <Upload size={34} />
                  <strong>{file ? file.name : "Choose an email file"}</strong>
                  <span>.eml or .txt · up to 5 MiB</span>
                  <input
                    id="email-file"
                    type="file"
                    accept=".eml,.txt"
                    onChange={(e) => setFile(e.target.files?.[0] || null)}
                  />
                </label>
                <Notice>
                  Files are validated and preserved locally. Attachments are
                  never executed.
                </Notice>
              </>
            ) : (
              <>
                <h2>Choose a simulation</h2>
                <p className="muted">
                  Fictional messages using reserved domains and inert
                  attachments. Each case is labelled as a simulation.
                </p>
                <div className="sample-list">
                  {samples?.map((s) => (
                    <label
                      className={`sample-option ${sample === s.id ? "chosen" : ""}`}
                      key={s.id}
                    >
                      <input
                        type="radio"
                        name="sample"
                        value={s.id}
                        checked={sample === s.id}
                        onChange={() => setSample(s.id)}
                      />
                      <span className="sample-symbol">
                        {s.id === "benign" ? <ShieldCheck /> : <Mail />}
                      </span>
                      <span>
                        <strong>{s.name}</strong>
                        <small>{s.description}</small>
                      </span>
                      <span className="sample-tag">
                        {s.id === "benign" ? "BENIGN" : "SIMULATION"}
                      </span>
                    </label>
                  ))}
                </div>
                <details>
                  <summary>Preview synthetic email</summary>
                  <pre>{samples?.find((s) => s.id === sample)?.raw_email}</pre>
                </details>
              </>
            )}
            {error && (
              <div className="form-error" role="alert">
                {error}
              </div>
            )}
            <div className="submit-row">
              <span>
                <Shield size={14} />
                Analysis runs locally
              </span>
              <Button disabled={busy}>
                {busy ? (
                  <LoaderCircle className="spin" size={17} />
                ) : (
                  <FileSearch size={17} />
                )}{" "}
                {busy ? "Analyzing evidence…" : "Start investigation"}
              </Button>
            </div>
          </div>
        </form>
        <aside className="submission-aside">
          <div className="eyebrow">FROM EMAIL TO EVIDENCE</div>
          <h2>
            A structured investigation,
            <br />
            in one workspace.
          </h2>
          <ol>
            {[
              "Parse email & preserve source",
              "Analyze headers & authenticity",
              "Extract and deduplicate indicators",
              "Map evidence to MITRE ATT&CK",
              "Assess risk & plan response",
              "Generate a professional report",
            ].map((s, i) => (
              <li key={s}>
                <span>{String(i + 1).padStart(2, "0")}</span>
                {s}
              </li>
            ))}
          </ol>
          <Notice>
            Local heuristic assessment — not externally verified. No URLs are
            visited and no email content is sent to external services.
          </Notice>
        </aside>
      </div>
    </>
  );
}

function History({ notify }: { notify: Notify }) {
  const [q, setQ] = useState(""),
    [severity, setSeverity] = useState("");
  const { data, error, refresh } = useResource<CaseSummary[]>(
    `/investigations?q=${encodeURIComponent(q)}&severity=${severity}`,
  );
  return (
    <>
      <PageHead
        title="Investigation history"
        description="Revisit evidence, findings, and reports across your investigations."
      >
        <Button asChild>
          <Link href="/new">
            <Plus size={16} />
            New investigation
          </Link>
        </Button>
      </PageHead>
      <div className="toolbar">
        <div className="search-field">
          <Search size={17} />
          <input
            aria-label="Search investigations"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by name, subject, sender or ID…"
          />
        </div>
        <select
          aria-label="Filter severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">All severities</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <Button
          variant="outline"
          onClick={async () => {
            await refresh();
            notify("Investigation list refreshed.");
          }}
        >
          <RefreshCw size={15} />
          Refresh
        </Button>
      </div>
      <Panel
        title="All investigations"
        subtitle={`${data?.length || 0} matching cases`}
      >
        {!data ? (
          <Load error={error} retry={refresh} />
        ) : data.length ? (
          <CaseTable cases={data} />
        ) : (
          <Empty title="No matching investigations">
            <Link href="/new">Start an investigation</Link> or adjust your
            search.
          </Empty>
        )}
      </Panel>
    </>
  );
}

function CasePicker({ mode }: { mode: "forensics" | "reports" }) {
  const { data, error, refresh } =
    useResource<CaseSummary[]>("/investigations");
  return (
    <>
      <PageHead
        title={mode === "reports" ? "Incident reports" : "Email forensics"}
        description={
          mode === "reports"
            ? "Review evidence-backed incident reports and export PDF, Markdown, or JSON."
            : "Select an investigation to inspect headers, authentication, MIME structure, and source evidence."
        }
      />
      <Panel
        title="Select an investigation"
        subtitle="Reports and forensic views use saved evidence"
      >
        {!data ? (
          <Load error={error} retry={refresh} />
        ) : data.length ? (
          <CaseTable
            cases={data}
            tab={mode === "reports" ? "report" : "email"}
          />
        ) : (
          <Empty title="No investigations yet">
            <Link href="/new">Submit an email to get started.</Link>
          </Empty>
        )}
      </Panel>
    </>
  );
}

function IOCPage({ notify }: { notify: Notify }) {
  return (
    <>
      <PageHead
        title="IOC intelligence"
        description="Trace extracted indicators back to evidence. Reputation stays unverified until checked."
      />
      <IOCTable notify={notify} />
    </>
  );
}
function IOCTable({ caseId, notify }: { caseId?: string; notify: Notify }) {
  const [q, setQ] = useState(""),
    [type, setType] = useState(""),
    [sort, setSort] = useState("value"),
    [selected, setSelected] = useState<IOC | null>(null),
    [provider, setProvider] = useState("virustotal"),
    [consent, setConsent] = useState(false),
    [busy, setBusy] = useState(false),
    [result, setResult] = useState<Intelligence | null>(null);
  const rememberOpener = useModalKeyboard(!!selected, () => setSelected(null));
  const params = new URLSearchParams({
    q,
    type,
    sort,
    ...(caseId ? { case_id: caseId } : {}),
  });
  const { data, error, refresh } = useResource<IOC[]>(`/iocs?${params}`);
  async function exportData(format: string) {
    try {
      await download(`/iocs/export/${format}?${params}`);
      notify(`${format.toUpperCase()} indicators exported.`);
    } catch (e) {
      notify((e as Error).message);
    }
  }
  async function enrich() {
    if (!selected) return;
    setBusy(true);
    try {
      setResult(
        await api<Intelligence>(
          `/investigations/${selected.investigation_id || caseId}/lookup`,
          {
            method: "POST",
            body: JSON.stringify({
              provider,
              indicator_id: selected.id,
              consent,
            }),
          },
        ),
      );
      await refresh();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Notice>
        Local heuristic assessment — not externally verified. Extracted values
        are evidence, not a declaration of maliciousness.
      </Notice>
      <div className="toolbar">
        <div className="search-field">
          <Search size={17} />
          <input
            aria-label="Search indicators"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search indicators…"
          />
        </div>
        <select
          aria-label="Filter IOC type"
          value={type}
          onChange={(e) => setType(e.target.value)}
        >
          <option value="">All IOC types</option>
          {[
            "url",
            "domain",
            "email",
            "ipv4",
            "ipv6",
            "md5",
            "sha1",
            "sha256",
            "filename",
          ].map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        <select
          aria-label="Sort indicators"
          value={sort}
          onChange={(e) => setSort(e.target.value)}
        >
          <option value="value">Sort: indicator</option>
          <option value="type">Sort: type</option>
          <option value="first_observed">Sort: first observed</option>
        </select>
        <Button variant="outline" onClick={() => exportData("csv")}>
          <ArrowDownToLine size={15} />
          CSV
        </Button>
        <Button variant="outline" onClick={() => exportData("json")}>
          JSON
        </Button>
      </div>
      <Panel
        title="Extracted indicators"
        subtitle={`${data?.length || 0} matching records · deduplicated within each investigation`}
      >
        {!data ? (
          <Load error={error} retry={refresh} />
        ) : !data.length ? (
          <Empty title="No indicators found">
            Adjust your filters or submit an email.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="ioc-table">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Reputation</th>
                  <th>Confidence</th>
                  <th>First observed</th>
                  <th>Case</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((i) => (
                  <tr key={`${i.investigation_id}-${i.id}`}>
                    <td>
                      <button
                        className="indicator-value"
                        onClick={(event) => {
                          rememberOpener(event.currentTarget);
                          setSelected(i);
                          setResult(null);
                          setConsent(false);
                        }}
                        title={defang(i.value)}
                      >
                        {defang(i.value)}
                      </button>
                    </td>
                    <td>
                      <span className="type-tag">{i.type}</span>
                    </td>
                    <td>{i.source}</td>
                    <td>
                      <Badge value={i.reputation} />
                    </td>
                    <td>{i.confidence}</td>
                    <td className="nowrap">{date(i.first_observed)}</td>
                    <td>
                      <Link
                        className="text-link mono"
                        href={`/investigations/${i.investigation_id}`}
                      >
                        {i.investigation_id?.slice(0, 8)}
                      </Link>
                    </td>
                    <td>
                      <button
                        aria-label={`Copy ${i.value}`}
                        className="icon-button"
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(i.value);
                            notify("Original indicator copied.");
                          } catch {
                            notify("Clipboard is unavailable in this browser.");
                          }
                        }}
                      >
                        <Clipboard size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {selected && (
        <div className="modal-backdrop" onClick={() => setSelected(null)}>
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="ioc-title"
            className="modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="panel-head">
              <h2 id="ioc-title">Indicator evidence</h2>
              <button
                autoFocus
                aria-label="Close indicator"
                className="icon-button"
                onClick={() => setSelected(null)}
              >
                <X />
              </button>
            </div>
            <div className="modal-body">
              <span className="type-tag">{selected.type}</span>
              <pre>{defang(selected.value)}</pre>
              <p>{selected.reason}</p>
              <dl className="metadata">
                <dt>Investigation</dt>
                <dd>{selected.investigation_id}</dd>
                <dt>Confidence</dt>
                <dd>{selected.confidence} confidence in extraction</dd>
                <dt>Reputation</dt>
                <dd>
                  {selected.reputation} — provider findings remain separate from
                  the local risk score.
                </dd>
              </dl>
              <h3>Evidence locations</h3>
              {selected.evidence.map((e, index) => (
                <div className="evidence" key={index}>
                  <strong>{e.source}</strong>
                  <code>{defang(e.excerpt)}</code>
                </div>
              ))}
              {!!selected.lookups?.length && (
                <>
                  <h3>Saved provider history</h3>
                  {selected.lookups.map((lookup, index) => (
                    <div className="evidence" key={index}>
                      <strong>
                        {lookup.provider} · {lookup.status} ·{" "}
                        {date(lookup.checked_at)}
                      </strong>
                      <p>{lookup.message}</p>
                      <p>
                        Reported reputation: {lookup.reputation}. No detections
                        does not establish safety.
                      </p>
                      {lookup.detections && (
                        <pre>{JSON.stringify(lookup.detections, null, 2)}</pre>
                      )}
                      {lookup.source_url && (
                        <a
                          className="text-link"
                          href={lookup.source_url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Provider source <ArrowRight size={14} />
                        </a>
                      )}
                    </div>
                  ))}
                </>
              )}
              <h3>Explicit external lookup</h3>
              <p className="muted">
                This sends the selected indicator to the provider.
                Private/reserved values, simulations, and URLs containing
                queries or credentials are blocked. No attachment or full email
                is submitted.
              </p>
              <select
                aria-label="Intelligence provider"
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
              >
                {["virustotal", "urlscan", "abuseipdb", "safebrowsing"].map(
                  (p) => (
                    <option key={p}>{p}</option>
                  ),
                )}
              </select>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(e) => setConsent(e.target.checked)}
                />
                I authorize disclosure of this public indicator to the selected
                provider.
              </label>
              <Button disabled={!consent || busy} onClick={enrich}>
                {busy ? "Checking provider…" : "Look up selected indicator"}
              </Button>
              {result && (
                <div className="lookup-result">
                  <Badge value={result.status} />
                  <p>{result.message}</p>
                  <p>
                    Reputation: {result.reputation} · {date(result.checked_at)}
                  </p>
                  {result.detections && (
                    <pre>{JSON.stringify(result.detections, null, 2)}</pre>
                  )}
                  {result.source_url && (
                    <a
                      className="text-link"
                      href={result.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Provider source <ArrowRight size={14} />
                    </a>
                  )}
                </div>
              )}
            </div>
          </section>
        </div>
      )}
    </>
  );
}

function MitreExplorer() {
  const { data, error, refresh } = useResource<Technique[]>("/techniques");
  const [q, setQ] = useState("");
  return (
    <>
      <PageHead
        title="MITRE ATT&CK explorer"
        description="A curated Enterprise ATT&CK subset for phishing investigations."
      />
      <Notice>
        Mappings require supporting evidence. Execution remains an unverified
        hypothesis unless recipient or endpoint activity establishes it.
      </Notice>
      <div className="toolbar">
        <div className="search-field">
          <Search size={17} />
          <input
            aria-label="Search techniques"
            placeholder="Search technique ID, name or tactic…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <a
          className="text-link"
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
        >
          Official MITRE ATT&CK <ArrowRight size={14} />
        </a>
      </div>
      {!data ? (
        <Load error={error} retry={refresh} />
      ) : (
        <div className="technique-grid">
          {data
            .filter((t) =>
              (t.id + t.name + t.tactic)
                .toLowerCase()
                .includes(q.toLowerCase()),
            )
            .map((t) => (
              <section className="panel technique" key={t.id}>
                <span className="eyebrow">{t.tactic}</span>
                <div className="technique-id">{t.id}</div>
                <h2>{t.name}</h2>
                <p>{t.description}</p>
                <a
                  href={t.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-link"
                >
                  Official technique reference <ArrowRight size={14} />
                </a>
              </section>
            ))}
        </div>
      )}
    </>
  );
}

function CaseDetail({ id, notify }: { id: string; notify: Notify }) {
  const params = useSearchParams(),
    tab = params.get("tab") || "overview";
  const {
    data: c,
    error,
    refresh,
  } = useResource<Investigation>(`/investigations/${id}`);
  const [notes, setNotes] = useState(""),
    [busy, setBusy] = useState(false),
    [deleteOpen, setDeleteOpen] = useState(false),
    [deleteText, setDeleteText] = useState("");
  const router = useRouter();
  const rememberDeleteOpener = useModalKeyboard(deleteOpen, () =>
    setDeleteOpen(false),
  );
  useEffect(() => {
    if (c) setNotes(c.notes);
  }, [c]);
  async function save() {
    setBusy(true);
    try {
      await api(`/investigations/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ notes }),
      });
      notify("Analyst notes saved.");
      await refresh();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function rerun() {
    setBusy(true);
    try {
      await api(`/investigations/${id}/reanalyze`, { method: "POST" });
      await refresh();
      notify(
        "New analysis revision saved. Original evidence and previous revisions retained.",
      );
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    setBusy(true);
    try {
      await api(`/investigations/${id}`, { method: "DELETE" });
      notify("Investigation and related records deleted.");
      router.push("/investigations");
    } catch (e) {
      notify((e as Error).message);
      setBusy(false);
    }
  }
  if (!c) return <Load error={error} retry={refresh} />;
  const a = c.analysis;
  const tabs = [
    ["overview", "Assessment"],
    ["email", "Email forensics"],
    ["iocs", "Indicators"],
    ["attack", "ATT&CK mapping"],
    ["response", "Response"],
    ["report", "Report"],
    ["history", "Evidence & history"],
  ];
  return (
    <>
      <Link className="back-link" href="/investigations">
        ← All investigations
      </Link>
      <PageHead
        eyebrow={`CASE ${id.slice(0, 8).toUpperCase()} ${c.simulation ? " / SIMULATION" : ""}`}
        title={c.name}
        description={`Created ${date(c.created_at)} · Local engine ${a.engine_version}`}
      >
        <Button variant="outline" disabled={busy} onClick={rerun}>
          <RefreshCw size={15} />
          Re-run analysis
        </Button>
        <Button asChild>
          <Link href={`/investigations/${id}?tab=report`}>
            <FileText size={16} />
            View report
          </Link>
        </Button>
      </PageHead>
      <div className="case-status">
        <Badge value={a.risk.severity} />
        <span>
          <Check size={14} />
          Analysis completed
        </span>
        <span>{a.iocs.length} indicators</span>
        <span>{a.findings.length} findings</span>
        <span className="mono">{id.slice(0, 8)}</span>
      </div>
      {c.simulation && (
        <Notice>
          SIMULATION — This investigation uses fictional email evidence,
          reserved domains, and inert attachment contents.
        </Notice>
      )}
      <div
        className="tabs case-tabs"
        role="tablist"
        aria-label="Investigation sections"
      >
        {tabs.map(([key, label]) => (
          <Link
            role="tab"
            aria-selected={tab === key}
            className={tab === key ? "selected" : ""}
            href={`/investigations/${id}?tab=${key}`}
            key={key}
          >
            {label}
            {key === "iocs" && <span>{a.iocs.length}</span>}
          </Link>
        ))}
      </div>
      {tab === "overview" ? (
        <>
          <div className="assessment-grid">
            <Panel title="Risk assessment" subtitle="Explainable local scoring">
              <div
                className="risk-number"
                style={{ color: colors[a.risk.severity] }}
              >
                {a.risk.score}
                <small>/100</small>
              </div>
              <Badge value={a.risk.severity} />
              <p className="muted">{a.risk.reasoning}</p>
              <div className="assessment-limit">
                <Shield size={17} />
                {a.risk.compromise}
              </div>
              <p className="muted">
                Assessment confidence: {a.risk.confidence}. External reputation
                is unknown until queried.
              </p>
            </Panel>
            <Panel title="Email at a glance" subtitle={a.parsed.subject}>
              <dl className="metadata">
                <dt>Sender</dt>
                <dd>{a.parsed.sender}</dd>
                <dt>Recipient</dt>
                <dd>{a.parsed.recipient}</dd>
                <dt>Reply-To</dt>
                <dd>{a.parsed.reply_to || "Not supplied"}</dd>
                <dt>Email date</dt>
                <dd>{a.parsed.date || "Unavailable"}</dd>
                <dt>Authentication</dt>
                <dd className="auth-inline">
                  {Object.entries(a.parsed.authentication).map(([k, v]) => (
                    <span key={k}>
                      {k.toUpperCase()} <Badge value={v.result} />
                    </span>
                  ))}
                </dd>
              </dl>
              <Notice>
                Authentication results are claims in the supplied headers.
                Gateway provenance is unverified.
              </Notice>
            </Panel>
          </div>
          <Panel
            title="Technical findings"
            subtitle="Each finding includes the observed evidence and its interpretation"
          >
            <Findings analysis={a} />
          </Panel>
          <Panel
            title="Analyst notes"
            subtitle="Included in incident report exports"
          >
            <div className="panel-content">
              <label htmlFor="analyst-notes" className="sr-only">
                Analyst notes
              </label>
              <textarea
                id="analyst-notes"
                rows={4}
                maxLength={20000}
                placeholder="Document your interpretation, verification steps, and follow-up evidence…"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
              <div className="right-actions">
                <Button disabled={busy} onClick={save}>
                  Save notes
                </Button>
              </div>
            </div>
          </Panel>
        </>
      ) : tab === "email" ? (
        <EmailForensics c={c} />
      ) : tab === "iocs" ? (
        <IOCTable caseId={id} notify={notify} />
      ) : tab === "attack" ? (
        <AttackChain mappings={a.mappings} />
      ) : tab === "response" ? (
        <>
          <Notice>
            Actions are conditional on the evidence. A suspicious message alone
            does not justify account disabling or infrastructure blocking.
          </Notice>
          <div className="response-list">
            {a.recommendations.map((r, i) => (
              <Panel
                key={r.phase}
                title={`${String(i + 1).padStart(2, "0")} / ${r.phase}`}
              >
                <div className="panel-content">
                  <h3>{r.action}</h3>
                  <p>{r.reason}</p>
                  <div className="finding-refs">
                    {r.evidence.map((id) => (
                      <span key={id}>{id}</span>
                    ))}
                  </div>
                </div>
              </Panel>
            ))}
          </div>
          <Panel title="Limitations and unknowns">
            <ul className="limitation-list">
              {a.limitations.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </Panel>
        </>
      ) : tab === "report" ? (
        <ReportView c={c} notify={notify} refresh={refresh} />
      ) : tab === "history" ? (
        <>
          <Panel
            title="Original evidence"
            subtitle="Preserved exact bytes; analysis revisions never overwrite the source"
          >
            <div className="panel-content">
              <label>SHA-256 integrity digest</label>
              <code className="hash">{c.evidence_sha256}</code>
              <Button
                variant="outline"
                onClick={async () => {
                  try {
                    await download(`/investigations/${id}/evidence`);
                  } catch (e) {
                    notify((e as Error).message);
                  }
                }}
              >
                <ArrowDownToLine size={16} />
                Download original .eml
              </Button>
            </div>
          </Panel>
          <Panel
            title="Analysis revision history"
            subtitle="Open a revision to compare the original and subsequent findings"
          >
            <div className="panel-content">
              {c.revisions.map((r, i) => (
                <RevisionRow
                  key={r.id}
                  caseId={id}
                  revision={r}
                  number={i + 1}
                />
              ))}
            </div>
          </Panel>
          <Panel title="Report export history">
            <div className="panel-content">
              {c.exports.length ? (
                c.exports.map((e) => (
                  <div className="history-row" key={e.id}>
                    <FileText size={17} />
                    <div>
                      <strong>{e.format.toUpperCase()} export</strong>
                      <p>
                        {date(e.created_at)} · Revision{" "}
                        {e.revision_id.slice(0, 8)}
                      </p>
                      <code>{e.sha256}</code>
                    </div>
                  </div>
                ))
              ) : (
                <p className="muted">No exports generated yet.</p>
              )}
            </div>
          </Panel>
          <Panel
            title="Delete investigation"
            subtitle="Permanently removes original evidence, revisions, intelligence records, notes and export history."
          >
            <div className="panel-content">
              <Button
                variant="destructive"
                onClick={(event) => {
                  rememberDeleteOpener(event.currentTarget);
                  setDeleteOpen(true);
                }}
              >
                <Trash2 size={16} />
                Delete investigation
              </Button>
            </div>
          </Panel>
        </>
      ) : (
        <Empty title="Unknown investigation section">
          <Link href={`/investigations/${id}`}>Return to assessment</Link>
        </Empty>
      )}
      {deleteOpen && (
        <div className="modal-backdrop">
          <section
            className="modal compact"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-title"
          >
            <div className="panel-head">
              <h2 id="delete-title">Delete this investigation?</h2>
              <button
                className="icon-button"
                aria-label="Cancel deletion"
                onClick={() => setDeleteOpen(false)}
              >
                <X />
              </button>
            </div>
            <div className="modal-body">
              <p>
                This permanently deletes the evidence and all related records.
                Type DELETE to confirm.
              </p>
              <input
                autoFocus
                aria-label="Confirm deletion"
                value={deleteText}
                onChange={(e) => setDeleteText(e.target.value)}
              />
              <div className="right-actions">
                <Button variant="outline" onClick={() => setDeleteOpen(false)}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  disabled={deleteText !== "DELETE" || busy}
                  onClick={remove}
                >
                  Permanently delete
                </Button>
              </div>
            </div>
          </section>
        </div>
      )}
    </>
  );
}

function Findings({ analysis: a }: { analysis: Analysis }) {
  return a.findings.length ? (
    <div className="findings">
      {a.findings.map((f) => (
        <details key={f.id} className="finding">
          <summary>
            <span className="finding-code">{f.id}</span>
            <ShieldAlert size={16} />
            <strong>{f.title}</strong>
            <span className="points">+{f.points} risk</span>
            <ChevronRight size={15} />
          </summary>
          <div>
            <p>{f.reason}</p>
            <div className="evidence">
              <span>OBSERVED EVIDENCE</span>
              <code>{defang(f.evidence)}</code>
            </div>
            <p className="muted">
              Confidence: {f.confidence} · {f.state}
            </p>
          </div>
        </details>
      ))}
    </div>
  ) : (
    <Empty title="No configured risk factors detected">
      Local checks did not flag this email. This does not guarantee safety.
    </Empty>
  );
}
function EmailForensics({ c }: { c: Investigation }) {
  const p = c.analysis.parsed;
  return (
    <>
      <div className="assessment-grid">
        <Panel title="Parsed email metadata">
          <dl className="metadata padded">
            {(
              [
                "sender",
                "recipient",
                "reply_to",
                "subject",
                "date",
                "message_id",
              ] as const
            ).map((k) => (
              <div className="metadata-pair" key={k}>
                <dt>{k.replace("_", " ")}</dt>
                <dd>{p[k] || "Not supplied"}</dd>
              </div>
            ))}
          </dl>
        </Panel>
        <Panel
          title="Authentication evidence"
          subtitle="Reported header claims; not independently validated"
        >
          <div className="panel-content">
            {Object.entries(p.authentication).map(([method, result]) => (
              <details className="auth-detail" key={method}>
                <summary>
                  <strong>{method.toUpperCase()}</strong>
                  <Badge value={result.result} />
                </summary>
                <p>{result.trust}</p>
                <pre>
                  {result.evidence.join("\n") ||
                    "No Authentication-Results evidence is available."}
                </pre>
              </details>
            ))}
          </div>
        </Panel>
      </div>
      <Panel
        title="Message body"
        subtitle="Text-only representation. HTML, links, forms, images and scripts are never rendered."
      >
        <div className="panel-content">
          <pre className="body-preview">
            {p.plain_text || p.html_text || "No text body."}
          </pre>
          {p.html_text && (
            <details>
              <summary>HTML body as inert text</summary>
              <pre>{p.html_text}</pre>
            </details>
          )}
        </div>
      </Panel>
      <Panel
        title="Attachments"
        subtitle="Metadata and hashes only — never executed or opened"
      >
        {p.attachments.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Declared MIME</th>
                  <th>Bytes</th>
                  <th>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {p.attachments.map((a) => (
                  <tr key={a.sha256 + a.filename}>
                    <td>{a.filename}</td>
                    <td>{a.content_type}</td>
                    <td>{a.size}</td>
                    <td className="mono break-all">{a.sha256}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="panel-content muted">No attachments present.</p>
        )}
      </Panel>
      <Panel title="MIME structure">
        <div className="panel-content">
          {p.mime.map((m) => (
            <div className="mime-row" key={m.index}>
              <span className="mono">PART {m.index}</span>
              <strong>{m.type}</strong>
              <span>
                {m.disposition || "inline"} {m.filename && `· ${m.filename}`}
              </span>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Complete headers">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Header</th>
                <th>Original value</th>
              </tr>
            </thead>
            <tbody>
              {p.headers.map((h, i) => (
                <tr key={i}>
                  <td className="mono">{h.name}</td>
                  <td className="break-all">{h.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <Panel title="Raw email evidence">
        <details className="panel-content">
          <summary>Expand original email text</summary>
          <pre>{c.raw_email}</pre>
        </details>
      </Panel>
      <Panel title="Forensic findings">
        <Findings analysis={c.analysis} />
      </Panel>
    </>
  );
}
function AttackChain({ mappings }: { mappings: Mapping[] }) {
  return (
    <>
      <Notice>
        Observed message characteristics support hypotheses. Delivery, recipient
        interaction, and execution are separate events; this analysis does not
        establish successful compromise.
      </Notice>
      <div className="attack-chain">
        <div>
          <Mail />
          <strong>Email evidence</strong>
          <span>Observed</span>
        </div>
        <ArrowRight />
        <div>
          <Target />
          <strong>Initial access attempt</strong>
          <span>
            {mappings.some((m) => m.tactic === "Initial Access")
              ? "Suspected"
              : "Not established"}
          </span>
        </div>
        <ArrowRight />
        <div>
          <Activity />
          <strong>User execution</strong>
          <span>Unverified</span>
        </div>
        <ArrowRight />
        <div>
          <Shield />
          <strong>Compromise</strong>
          <span>No evidence</span>
        </div>
      </div>
      {mappings.length ? (
        <div className="mapping-list">
          {mappings.map((m) => (
            <Panel
              key={m.id}
              title={`${m.id} / ${m.name}`}
              subtitle={`${m.tactic} · Confidence: ${m.confidence}`}
              action={<Badge value={m.state} />}
            >
              <div className="panel-content">
                <p>{m.description}</p>
                <p>{m.justification}</p>
                <div className="evidence">
                  <span>SUPPORTING EVIDENCE</span>
                  <code>{m.evidence.map(defang).join("\n")}</code>
                </div>
                <a
                  href={m.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-link"
                >
                  Official MITRE reference <ArrowRight size={14} />
                </a>
              </div>
            </Panel>
          ))}
        </div>
      ) : (
        <Empty title="No supported ATT&CK mappings">
          Available email evidence does not meet the local mapping rules.
        </Empty>
      )}
    </>
  );
}
function RevisionRow({
  caseId,
  revision: r,
  number,
}: {
  caseId: string;
  revision: { id: string; created_at: string; engine_version: string };
  number: number;
}) {
  const [analysis, setAnalysis] = useState<Analysis | null>(null),
    [error, setError] = useState("");
  return (
    <details
      className="revision"
      onToggle={async (e) => {
        if (e.currentTarget.open && !analysis) {
          try {
            setAnalysis(
              await api(`/investigations/${caseId}/revisions/${r.id}`),
            );
          } catch (e) {
            setError((e as Error).message);
          }
        }
      }}
    >
      <summary>
        <span>
          Revision {number} ·{" "}
          {number === 1 ? "Original analysis" : "Subsequent analysis"}
        </span>
        <span>{date(r.created_at)}</span>
      </summary>
      {error && <p role="alert">{error}</p>}
      {analysis && (
        <div>
          <p>
            Engine {r.engine_version} · <Badge value={analysis.risk.severity} />{" "}
            · {analysis.risk.score}/100 · {analysis.iocs.length} indicators
          </p>
          <Findings analysis={analysis} />
        </div>
      )}
    </details>
  );
}
function ReportView({
  c,
  notify,
  refresh,
}: {
  c: Investigation;
  notify: Notify;
  refresh: () => Promise<void>;
}) {
  const {
    data,
    error,
    refresh: reload,
  } = useResource<{
    markdown: string;
    sections: [string, ...Array<Array<string | string[]>>][];
    settings: Preferences;
  }>(`/investigations/${c.id}/report`);
  const [busy, setBusy] = useState("");
  async function exportReport(format: string) {
    setBusy(format);
    try {
      await download(`/investigations/${c.id}/report/${format}`);
      notify(`${format.toUpperCase()} report exported.`);
      await refresh();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  return (
    <>
      <div className="report-toolbar">
        <div>
          <h2>Incident investigation report</h2>
          <p>19 sections · Actual stored evidence · Analyst notes included</p>
        </div>
        <div>
          {["pdf", "md", "json"].map((format) => (
            <Button
              key={format}
              variant={format === "pdf" ? "default" : "outline"}
              disabled={!!busy}
              onClick={() => exportReport(format)}
            >
              <ArrowDownToLine size={15} />
              {busy === format ? "Generating…" : format.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>
      {!data ? (
        <Load error={error} retry={reload} />
      ) : (
        <article className="report-paper">
          <div className="report-brand">
            <ShieldCheck />
            PHISHSCOPE <span>INCIDENT REPORT</span>
          </div>
          <div className="report-classification">
            {data.settings.classification} /{" "}
            {c.simulation ? "SIMULATION / " : ""}EVIDENCE-BASED ASSESSMENT
          </div>
          <h2>{c.name}</h2>
          <p className="mono">{c.id}</p>
          <div className="report-risk">
            <strong>{c.risk.severity.toUpperCase()}</strong>
            <span>{c.risk.score}/100 · Local risk score</span>
          </div>
          {data.sections.map(([title, ...blocks]) => {
            const items = blocks.flat();
            const rows = items.filter(Array.isArray) as string[][];
            const paragraphs = items.filter(
              (item): item is string => typeof item === "string",
            );
            return (
              <section className="report-section" key={title}>
                <h3>{title}</h3>
                {rows.length > 0 && (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          {rows[0].map((cell, index) => (
                            <th key={index}>{cell}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {rows.slice(1).map((row, index) => (
                          <tr key={index}>
                            {row.map((cell, index) => (
                              <td key={index}>{cell}</td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {paragraphs.map((paragraph, index) => (
                  <p key={index}>{paragraph}</p>
                ))}
              </section>
            );
          })}
        </article>
      )}
    </>
  );
}

function SettingsPage({ notify }: { notify: Notify }) {
  const { data: s, error, refresh } = useResource<Settings>("/settings");
  const [p, setP] = useState<Preferences | null>(null),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    if (s) setP(s.preferences);
  }, [s]);
  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api("/settings", { method: "PATCH", body: JSON.stringify(p) });
      notify("Workspace preferences saved.");
      await refresh();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!s || !p) return <Load error={error} retry={refresh} />;
  return (
    <>
      <PageHead
        title="Settings"
        description="Configure your local workspace, reporting defaults, and intelligence providers."
      />
      <div className="settings-grid">
        <Panel
          title="Workspace & reports"
          subtitle="Used in all new report exports"
        >
          <form className="form-body" onSubmit={save}>
            <label htmlFor="organization">Organization</label>
            <input
              id="organization"
              value={p.organization}
              maxLength={200}
              required
              onChange={(e) => setP({ ...p, organization: e.target.value })}
            />
            <label htmlFor="analyst">Analyst name</label>
            <input
              id="analyst"
              value={p.analyst_name}
              maxLength={100}
              required
              onChange={(e) => setP({ ...p, analyst_name: e.target.value })}
            />
            <label htmlFor="classification">Default classification</label>
            <select
              id="classification"
              value={p.classification}
              onChange={(e) =>
                setP({
                  ...p,
                  classification: e.target
                    .value as Preferences["classification"],
                })
              }
            >
              {["CONFIDENTIAL", "INTERNAL", "PUBLIC"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
            <label htmlFor="default-input">Default submission method</label>
            <select
              id="default-input"
              value={p.default_input}
              onChange={(e) =>
                setP({
                  ...p,
                  default_input: e.target.value as Preferences["default_input"],
                })
              }
            >
              <option value="paste">Paste raw email</option>
              <option value="upload">Upload email file</option>
              <option value="sample">Demonstration</option>
            </select>
            <div className="right-actions">
              <Button disabled={busy}>
                {busy ? "Saving…" : "Save preferences"}
              </Button>
            </div>
          </form>
        </Panel>
        <Panel title="Application" subtitle="PhishScope 1.0.0">
          <dl className="metadata padded">
            <dt>Analysis mode</dt>
            <dd>Offline-first, static heuristics</dd>
            <dt>Database</dt>
            <dd>{s.database}</dd>
            <dt>Upload limit</dt>
            <dd>{s.max_upload_mb} MiB / .eml and .txt</dd>
            <dt>Stored investigations</dt>
            <dd>{s.investigations}</dd>
            <dt>Evidence handling</dt>
            <dd>Original bytes + SHA-256 digest</dd>
          </dl>
          <div className="panel-content">
            <Notice>
              This is a single-analyst local application. Network or multi-user
              deployment requires an authenticated access boundary.
            </Notice>
          </div>
        </Panel>
      </div>
      <Panel
        title="Threat intelligence integrations"
        subtitle="Credentials stay in backend environment variables. No keys are returned to the browser."
      >
        <div className="provider-grid">
          {s.providers.map((provider) => (
            <section className="provider" key={provider.id}>
              <div>
                <Globe size={20} />
                <Badge
                  value={provider.configured ? "configured" : "not configured"}
                />
              </div>
              <h3>
                {
                  {
                    virustotal: "VirusTotal",
                    urlscan: "URLScan.io",
                    abuseipdb: "AbuseIPDB",
                    safebrowsing: "Google Safe Browsing",
                  }[provider.id]
                }
              </h3>
              <p>
                Last API status: {provider.last_status}
                {provider.last_checked && ` · ${date(provider.last_checked)}`}
              </p>
              <code>{provider.environment_variable}</code>
              <p>
                {provider.configured
                  ? "Configured. Operational status is established only after an explicit IOC lookup."
                  : "Set this variable in the root .env file, then restart the backend."}
              </p>
            </section>
          ))}
        </div>
        <div className="panel-content">
          <Notice>
            Configuration does not verify credentials. Use an indicator detail
            view to explicitly request a lookup. URLScan and VirusTotal retrieve
            existing records only; no scans are submitted.
          </Notice>
        </div>
      </Panel>
      <Panel
        title="Data management"
        subtitle="Evidence is sensitive. Keep the data directory private and include it in your backup policy."
      >
        <div className="panel-content">
          <p>
            Review and delete individual cases from Evidence & history. Each
            deletion requires typed confirmation and removes all associated
            database records.
          </p>
          <Button asChild variant="outline">
            <Link href="/investigations">
              Manage investigations <ArrowRight size={15} />
            </Link>
          </Button>
        </div>
      </Panel>
    </>
  );
}

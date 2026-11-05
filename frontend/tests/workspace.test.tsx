import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Workspace from "../src/components/workspace";

const state = vi.hoisted(() => ({ path: "/", push: vi.fn() }));
vi.mock("next/navigation", () => ({
  usePathname: () => state.path,
  useRouter: () => ({ push: state.push }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("next/link", () => ({
  default: ({
    children,
    ...props
  }: {
    children: React.ReactNode;
    href: string;
  }) => <a {...props}>{children}</a>,
}));
vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  AreaChart: () => null,
  PieChart: () => null,
  Area: () => null,
  CartesianGrid: () => null,
  Cell: () => null,
  Pie: () => null,
  Tooltip: () => null,
  XAxis: () => null,
  YAxis: () => null,
}));
const prefs = {
  analyst_name: "SOC Analyst",
  classification: "CONFIDENTIAL",
  organization: "Test SOC",
  default_input: "paste",
};
const settings = {
  preferences: prefs,
  providers: [
    {
      id: "virustotal",
      configured: false,
      environment_variable: "VIRUSTOTAL_API_KEY",
      last_status: "untested",
    },
  ],
  version: "1.0.0",
  max_upload_mb: 5,
  database: "SQLite",
  investigations: 0,
};
function mockFetch(routes: Record<string, unknown>) {
  const fn = vi.fn(async (input: string, init?: RequestInit) => {
    const key = input.split("?")[0];
    const value = routes[key] ?? {};
    return {
      ok: true,
      status: 200,
      json: async () => value,
      ...(init?.method === "POST" && key === "/api/investigations"
        ? { json: async () => ({ id: "created-case" }) }
        : {}),
    };
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}
beforeEach(() => {
  state.path = "/";
  state.push.mockClear();
});
describe("workspace", () => {
  it("renders genuine empty dashboard and all navigation destinations", async () => {
    mockFetch({
      "/api/dashboard": {
        total: 0,
        completed: 0,
        pending: 0,
        confirmed_malicious: 0,
        severities: { critical: 0, high: 0, medium: 0, low: 0 },
        ioc_categories: {},
        timeline: [],
        recent: [],
      },
    });
    render(<Workspace />);
    expect(
      await screen.findByRole("heading", { name: "Investigation overview" }),
    ).toBeInTheDocument();
    expect(screen.getByText("No investigations yet")).toBeInTheDocument();
    expect(
      within(screen.getByRole("navigation")).getAllByRole("link"),
    ).toHaveLength(8);
    expect(
      screen.getByRole("button", { name: "Load demonstration cases" }),
    ).toBeEnabled();
  });
  it("submits pasted email to backend and opens saved case", async () => {
    state.path = "/new";
    const fetch = mockFetch({ "/api/samples": [], "/api/settings": settings });
    render(<Workspace />);
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith("/api/settings", expect.anything()),
    );
    fireEvent.change(screen.getByLabelText("Investigation name"), {
      target: { value: "Test case" },
    });
    fireEvent.change(screen.getByLabelText(/Raw email evidence/), {
      target: { value: "From: a@b.test\nSubject: Sample\n\nHello" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Start investigation" }),
    );
    await waitFor(() =>
      expect(state.push).toHaveBeenCalledWith("/investigations/created-case"),
    );
    expect(fetch).toHaveBeenCalledWith(
      "/api/investigations",
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining("Test case"),
      }),
    );
  });
  it("switches upload and demonstration inputs", async () => {
    state.path = "/new";
    mockFetch({
      "/api/samples": [
        {
          id: "account",
          name: "Account security phishing",
          description: "Test scenario",
          raw_email: "From: test",
          simulation: true,
        },
      ],
      "/api/settings": settings,
    });
    render(<Workspace />);
    await screen.findByLabelText("Investigation name");
    await waitFor(() =>
      expect(
        screen.getByRole("tab", { name: "Paste raw email" }),
      ).toHaveAttribute("aria-selected", "true"),
    );
    fireEvent.click(screen.getByRole("tab", { name: "Upload email" }));
    expect(screen.getByLabelText(/Choose an email file/)).toHaveAttribute(
      "accept",
      ".eml,.txt",
    );
    fireEvent.click(screen.getByRole("tab", { name: "Demonstration" }));
    expect(
      await screen.findByText("Account security phishing"),
    ).toBeInTheDocument();
    expect(screen.getByRole("radio")).toBeChecked();
  });
  it("renders searchable IOC evidence and export controls", async () => {
    state.path = "/iocs";
    mockFetch({
      "/api/iocs": [
        {
          id: "ioc1",
          value: "https://sample.example/login",
          type: "url",
          source: "HTML href",
          reason: "Extracted",
          reputation: "unverified",
          confidence: "high",
          first_observed: "2026-11-05T09:00:00Z",
          investigation_id: "case1234",
          evidence: [
            { source: "HTML href", excerpt: "https://sample.example/login" },
          ],
        },
      ],
    });
    render(<Workspace />);
    expect(
      await screen.findByRole("button", {
        name: "hxxps://sample[.]example/login",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "CSV" })).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "hxxps://sample[.]example/login" }),
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Look up selected indicator" }),
    ).toBeDisabled();
  });
  it("filters MITRE techniques", async () => {
    state.path = "/mitre";
    mockFetch({
      "/api/techniques": [
        {
          id: "T1566.001",
          name: "Spearphishing Attachment",
          tactic: "Initial Access",
          description: "Attachment delivery",
          url: "https://attack.mitre.org/techniques/T1566/001/",
        },
        {
          id: "T1566.002",
          name: "Spearphishing Link",
          tactic: "Initial Access",
          description: "Link delivery",
          url: "https://attack.mitre.org/techniques/T1566/002/",
        },
      ],
    });
    render(<Workspace />);
    await screen.findByText("Spearphishing Attachment");
    fireEvent.change(screen.getByLabelText("Search techniques"), {
      target: { value: "T1566.002" },
    });
    expect(
      screen.queryByText("Spearphishing Attachment"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Spearphishing Link")).toBeInTheDocument();
  });
  it("saves report defaults without accepting or displaying secret keys", async () => {
    state.path = "/settings";
    const fetch = mockFetch({ "/api/settings": settings });
    render(<Workspace />);
    fireEvent.change(await screen.findByLabelText("Analyst name"), {
      target: { value: "New Analyst" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        "/api/settings",
        expect.objectContaining({
          method: "PATCH",
          body: expect.stringContaining("New Analyst"),
        }),
      ),
    );
    expect(screen.getByText("VIRUSTOTAL_API_KEY")).toBeInTheDocument();
  });
  it("shows API errors with a retry action", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("Backend unavailable")),
    );
    render(<Workspace />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Backend unavailable",
    );
    expect(screen.getByRole("button", { name: "Try again" })).toBeEnabled();
  });
});

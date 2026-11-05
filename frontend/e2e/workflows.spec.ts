import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import path from "node:path";
import fs from "node:fs";

const ids: string[] = [];

test("indicator consent, keyboard dismissal, revision view and confirmed deletion", async ({
  page,
  request,
}) => {
  const response = await request.post("/api/investigations", {
    data: {
      name: "Indicator and deletion workflow",
      raw_email:
        "From: a@sample.example\nSubject: Review\nDate: Thu, 05 Nov 2026 09:00:00 +0000\nMessage-ID: <test@sample.example>\n\nReview https://review.example/check",
    },
  });
  expect(response.ok()).toBeTruthy();
  const c = await response.json();
  ids.push(c.id);
  await page.goto(`/investigations/${c.id}?tab=iocs`);
  const indicator = page.getByRole("button", {
    name: "hxxps://review[.]example/check",
    exact: true,
  });
  await indicator.click();
  await expect(
    page.getByRole("button", { name: "Look up selected indicator" }),
  ).toBeDisabled();
  await page.getByRole("checkbox").check();
  await page
    .getByRole("button", { name: "Look up selected indicator" })
    .click();
  await expect(page.locator(".lookup-result")).toContainText("blocked");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(indicator).toBeFocused();
  for (const format of ["JSON"]) {
    const pending = page.waitForEvent("download");
    await page.getByRole("button", { name: format, exact: true }).click();
    expect((await pending).suggestedFilename()).toMatch(/\.json$/);
  }
  await page.getByRole("tab", { name: "Evidence & history" }).click();
  await page.getByText("Revision 1 · Original analysis").click();
  await expect(page.locator(".revision")).toContainText("Engine 1.0.0");
  await page
    .getByRole("button", { name: "Delete investigation", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Permanently delete" }),
  ).toBeDisabled();
  await page.getByLabel("Confirm deletion").fill("DELETE");
  await page.getByRole("button", { name: "Permanently delete" }).click();
  await expect(page).toHaveURL(/\/investigations$/);
  expect((await request.get(`/api/investigations/${c.id}`)).status()).toBe(404);
});
test.afterAll(async ({ request }) => {
  for (const id of ids) await request.delete(`/api/investigations/${id}`);
});

test("complete phishing investigation, report PDF and persisted findings", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Investigation overview" }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "New investigation", exact: true })
    .last()
    .click();
  await page.getByRole("tab", { name: "Demonstration" }).click();
  await page.getByRole("radio", { name: /Account security phishing/ }).check();
  await page.getByRole("button", { name: "Start investigation" }).click();
  await expect(page).toHaveURL(/\/investigations\/[a-f0-9-]+$/);
  const id = page.url().split("/").pop()!;
  ids.push(id);
  await expect(
    page.getByRole("heading", {
      name: "Account security phishing",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByText("No evidence of successful compromise", { exact: true }),
  ).toBeVisible();
  await page.getByRole("tab", { name: "Email forensics" }).click();
  await expect(
    page
      .getByText("Microsoft Security <security@verify-account.example>", {
        exact: true,
      })
      .first(),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Authentication evidence" }),
  ).toBeVisible();
  await page.getByRole("tab", { name: /Indicators/ }).click();
  await expect(
    page.getByRole("button", {
      name: "hxxps://verify-account[.]example/login",
      exact: true,
    }),
  ).toBeVisible();
  await page.getByLabel("Filter IOC type").selectOption("url");
  await page.getByLabel("Search indicators").fill("verify-account");
  await expect(page.locator("tbody tr")).toHaveCount(2);
  const csv = page.waitForEvent("download");
  await page.getByRole("button", { name: "CSV", exact: true }).click();
  expect((await csv).suggestedFilename()).toMatch(/\.csv$/);
  await page.getByRole("tab", { name: "ATT&CK mapping" }).click();
  await expect(
    page.getByRole("heading", { name: "T1566.002 / Spearphishing Link" }),
  ).toBeVisible();
  await expect(page.getByText("User execution", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "Response", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "02 / Containment" }),
  ).toBeVisible();
  await page.getByRole("tab", { name: "Assessment", exact: true }).click();
  await page
    .getByLabel("Analyst notes", { exact: true })
    .fill("E2E analyst note: no recipient interaction established.");
  await page.getByRole("button", { name: "Save notes" }).click();
  await expect(page.getByRole("status")).toContainText("Analyst notes saved.");
  await page.getByRole("tab", { name: "Report", exact: true }).click();
  await expect(page.locator(".report-paper")).toContainText(
    "Executive Summary",
  );
  await expect(page.locator(".report-paper")).toContainText("E2E analyst note");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "PDF", exact: true }).click();
  const pdf = await downloadPromise;
  const filename = path.resolve("test-results", "phishscope-e2e-report.pdf");
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  await pdf.saveAs(filename);
  expect(fs.readFileSync(filename).subarray(0, 4).toString()).toBe("%PDF");
  const python =
    process.platform === "win32"
      ? path.resolve("..", ".venv", "Scripts", "python.exe")
      : path.resolve("..", ".venv", "bin", "python");
  const content = execFileSync(
    python,
    [
      "-c",
      'from pypdf import PdfReader; import sys; print("\\n".join(p.extract_text() for p in PdfReader(sys.argv[1]).pages))',
      filename,
    ],
    { encoding: "utf8" },
  );
  expect(content).toContain("T1566.002");
  expect(content).toContain("E2E analyst note");
  expect(content).toContain("verify-account.example");
  await page.goto("/investigations");
  await page
    .getByRole("link", {
      name: new RegExp(`Account security phishing.*${id.slice(0, 8)}`, "i"),
    })
    .click();
  await expect(page.getByLabel("Analyst notes", { exact: true })).toHaveValue(
    "E2E analyst note: no recipient interaction established.",
  );
  await page.getByRole("button", { name: "Re-run analysis" }).click();
  await expect(page.getByRole("status")).toContainText(
    "New analysis revision saved",
  );
  await page.getByRole("tab", { name: "Evidence & history" }).click();
  await expect(
    page.getByText("Revision 2 · Subsequent analysis"),
  ).toBeVisible();
  expect(errors).toEqual([]);
});

test("benign email stays low risk with no ATT&CK mapping", async ({ page }) => {
  await page.goto("/new");
  await page.getByRole("tab", { name: "Demonstration" }).click();
  await page.getByRole("radio", { name: /Legitimate business email/ }).check();
  await page.getByRole("button", { name: "Start investigation" }).click();
  await expect(page).toHaveURL(/\/investigations\/[a-f0-9-]+$/);
  ids.push(page.url().split("/").pop()!);
  await expect(
    page.getByText("No configured risk factors detected", { exact: true }),
  ).toBeVisible();
  await expect(page.locator(".risk-number")).toContainText("0/100");
  await page.getByRole("tab", { name: "ATT&CK mapping" }).click();
  await expect(
    page.getByRole("heading", { name: "No supported ATT&CK mappings" }),
  ).toBeVisible();
});

test("paste and upload workflows preserve evidence, settings and navigation work", async ({
  page,
  request,
}) => {
  const raw =
    "From: Taylor <taylor@company.example>\nTo: analyst@company.example\nSubject: E2E planning message\nDate: Thu, 05 Nov 2026 09:00:00 +0000\nMessage-ID: <e2e@company.example>\n\nAgenda for the planning session.";
  await page.goto("/new");
  await page.getByRole("tab", { name: "Paste raw email" }).click();
  await page.getByLabel("Investigation name").fill("Pasted E2E case");
  await page.getByLabel("Raw email evidence").fill(raw);
  await page.getByRole("button", { name: "Start investigation" }).click();
  await expect(page).toHaveURL(/\/investigations\/[a-f0-9-]+$/);
  ids.push(page.url().split("/").pop()!);
  await page.goto("/new");
  await page.getByRole("tab", { name: "Upload email" }).click();
  await page.locator("#email-file").setInputFiles({
    name: "uploaded-evidence.eml",
    mimeType: "message/rfc822",
    buffer: Buffer.from(raw),
  });
  await page.getByRole("button", { name: "Start investigation" }).click();
  await expect(page).toHaveURL(/\/investigations\/[a-f0-9-]+$/);
  const id = page.url().split("/").pop()!;
  ids.push(id);
  expect(
    (
      await (await request.get(`/api/investigations/${id}/evidence`)).body()
    ).toString(),
  ).toBe(raw);
  await page.goto("/settings");
  await expect(page.getByLabel("Analyst name")).toBeVisible();
  await page.getByLabel("Analyst name").fill("SOC Analyst");
  await page.getByRole("button", { name: "Save preferences" }).click();
  await expect(page.getByRole("status")).toContainText(
    "Workspace preferences saved",
  );
  for (const [url, heading] of [
    ["/forensics", "Email forensics"],
    ["/iocs", "IOC intelligence"],
    ["/mitre", "MITRE ATT&CK explorer"],
    ["/reports", "Incident reports"],
  ]) {
    await page.goto(url);
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
  }
  await page.getByRole("link", { name: /Open uploaded-evidence.eml/ }).click();
  await expect(page.locator(".report-paper")).toContainText(
    "E2E planning message",
  );
});

test("responsive navigation and stored email XSS remain inert", async ({
  page,
  request,
}) => {
  const response = await request.post("/api/investigations", {
    data: {
      name: "XSS isolation test",
      raw_email:
        'From: a@example.test\nSubject: <img src=x onerror=alert(1)>\nContent-Type: text/html\n\n<script>window.XSS_EXECUTED=true</script><img src="https://tracking.invalid/pixel"><a href="javascript:alert(1)">Click</a>',
    },
  });
  expect(response.ok()).toBeTruthy();
  const c = await response.json();
  ids.push(c.id);
  await page.goto(`/investigations/${c.id}?tab=email`);
  expect(await page.evaluate(() => "XSS_EXECUTED" in window)).toBe(false);
  await expect(page.locator("main img, main iframe, main script")).toHaveCount(
    0,
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Toggle navigation" }).click();
  await page.getByRole("link", { name: "Overview", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Investigation overview" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    ),
  ).toBe(false);
});

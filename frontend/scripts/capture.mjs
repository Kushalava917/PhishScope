// Run with both services active: node scripts/capture.mjs
import { chromium } from "playwright";
import fs from "node:fs/promises";
import path from "node:path";

const directory = path.resolve("..", "docs", "screenshots");
await fs.mkdir(directory, { recursive: true });
const browser = await chromium.launch();
try {
  const page = await browser.newPage({
    viewport: { width: 1512, height: 1100 },
    deviceScaleFactor: 1,
  });
  await page.request.post("http://127.0.0.1:3000/api/demo");
  const cases = await (
    await page.request.get("http://127.0.0.1:3000/api/investigations")
  ).json();
  const sample = cases.find(
    (c) => c.simulation && c.name === "Account security phishing",
  );
  await page.goto("http://127.0.0.1:3000");
  await page.getByRole("heading", { name: "Investigation overview" }).waitFor();
  await page.waitForTimeout(2300); // Allow the chart's entry animation to finish.
  await page.screenshot({
    path: path.join(directory, "overview.png"),
    fullPage: true,
  });
  await page.goto(`http://127.0.0.1:3000/investigations/${sample.id}`);
  await page.getByRole("heading", { name: "Technical findings" }).waitFor();
  await page.screenshot({
    path: path.join(directory, "investigation.png"),
    fullPage: true,
  });
  await page.goto(
    `http://127.0.0.1:3000/investigations/${sample.id}?tab=report`,
  );
  await page.locator(".report-paper").waitFor();
  await page.screenshot({
    path: path.join(directory, "report.png"),
    fullPage: true,
  });
  const pdf = await page.request.get(
    `http://127.0.0.1:3000/api/investigations/${sample.id}/report/pdf`,
  );
  if (!pdf.ok()) throw new Error("Sample report export failed");
  await fs.writeFile(
    path.resolve("..", "docs", "sample-incident-report.pdf"),
    await pdf.body(),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("http://127.0.0.1:3000");
  await page.getByRole("heading", { name: "Investigation overview" }).waitFor();
  await page.waitForTimeout(2300);
  await page.screenshot({
    path: path.join(directory, "mobile.png"),
    fullPage: true,
  });
  console.log(
    JSON.stringify({
      screenshots: directory,
      sampleCase: sample.id,
      totalInvestigations: cases.length,
    }),
  );
} finally {
  await browser.close();
}

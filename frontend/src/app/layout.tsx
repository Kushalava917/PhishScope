import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "PhishScope | Investigation workspace",
  description: "Evidence-led phishing incident investigation and reporting.",
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

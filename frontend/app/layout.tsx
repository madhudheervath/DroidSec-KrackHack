import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "DroidSec — APK Security Analyzer",
  description:
    "Static security analysis for Android APK files. Detect vulnerabilities, map to OWASP Mobile Top 10, and generate professional security reports.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-black text-gray-50 antialiased min-h-screen`}>
        {children}
      </body>
    </html>
  );
}

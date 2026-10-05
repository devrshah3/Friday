import type { Metadata, Viewport } from "next";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: "F.R.I.D.A.Y.",
  description: "Female Replacement Intelligent Digital Assistant Youth",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "FRIDAY",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  viewportFit: "cover",
  themeColor: "#000a19",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        {/* iOS standalone web app */}
        <link rel="apple-touch-icon" href="/icon-192.png" />
      </head>
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}

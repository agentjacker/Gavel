import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Gavel - AI-Powered Vulnerability Verification',
  description: 'Verify vulnerability reports against codebases using advanced AI models',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="font-mono antialiased bg-white text-black">
        {children}
      </body>
    </html>
  )
}

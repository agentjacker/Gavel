import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Gavel — Vulnerability triage',
  description: 'Self-hosted vulnerability verification with organization context and evidence-based decisions.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        {children}
      </body>
    </html>
  )
}

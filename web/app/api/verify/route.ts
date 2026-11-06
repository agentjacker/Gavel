import { NextResponse } from 'next/server'

// Retired: reports must never select code repositories or execute shell commands.
export async function POST() {
  return NextResponse.json(
    { error: 'This intake has been retired. Submit reports through the configured Gavel program.' },
    { status: 410, headers: { 'Cache-Control': 'no-store' } },
  )
}

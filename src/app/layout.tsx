import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Secure AI Rules Directory',
  description: 'Comprehensive security guidelines for building safe, reliable, and compliant AI systems.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}

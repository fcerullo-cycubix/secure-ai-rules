import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: {
    default: 'Secure AI Rules Directory - AI Security Guidelines & Best Practices 2025',
    template: '%s | Secure AI Rules Directory'
  },
  description: 'Comprehensive security guidelines, rules, and best practices for building safe, reliable, and compliant AI systems. Covers Angular, Python, Ruby, Node.js, Java, and .NET security.',
  keywords: [
    'AI security',
    'artificial intelligence security',
    'machine learning security',
    'AI compliance',
    'secure AI development',
    'AI governance',
    'ML security guidelines',
    'Python AI security',
    'Node.js AI security',
    'Angular security',
    'Ruby security',
    'Java security',
    '.NET security',
    'prompt injection defense',
    'AI risk management',
    'secure coding practices',
    'AI safety guidelines'
  ],
  authors: [{ name: 'Secure AI Rules Directory' }],
  creator: 'Secure AI Rules Directory',
  publisher: 'Secure AI Rules Directory',
  category: 'Technology',
  classification: 'AI Security Guidelines',
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://secure-ai-dev.cycubix.com',
    title: 'Secure AI Rules Directory - AI Security Guidelines & Best Practices 2025',
    description: 'Comprehensive security guidelines, rules, and best practices for building safe, reliable, and compliant AI systems. Updated for 2025.',
    siteName: 'Secure AI Rules Directory',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: 'Secure AI Rules Directory - AI Security Guidelines',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Secure AI Rules Directory - AI Security Guidelines 2025',
    description: 'Comprehensive security guidelines for building safe AI systems. Covers Python, Node.js, Angular, Ruby, Java, .NET.',
    images: ['/twitter-image.png'],
    creator: '@secure_ai_rules',
  },
  alternates: {
    canonical: 'https://secure-ai-dev.cycubix.com',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "name": "Secure AI Rules Directory",
    "description": "Comprehensive security guidelines, rules, and best practices for building safe, reliable, and compliant AI systems.",
    "url": "https://secure-ai-dev.cycubix.com",
    "author": {
      "@type": "Organization",
      "name": "Secure AI Rules Directory"
    },
    "publisher": {
      "@type": "Organization",
      "name": "Secure AI Rules Directory"
    },
    "potentialAction": {
      "@type": "SearchAction",
      "target": "https://secure-ai-dev.cycubix.com/secure-ai-rules?search={search_term_string}",
      "query-input": "required name=search_term_string"
    },
    "mainEntity": {
      "@type": "ItemList",
      "name": "AI Security Guidelines",
      "description": "Collection of security rules and best practices for AI development",
      "numberOfItems": 6,
      "itemListElement": [
        {
          "@type": "SoftwareApplication",
          "name": "Angular Security Guidelines",
          "description": "Security best practices for Angular applications in AI systems"
        },
        {
          "@type": "SoftwareApplication",
          "name": "Python Security Guidelines",
          "description": "Security practices for Python applications and AI/ML frameworks"
        },
        {
          "@type": "SoftwareApplication",
          "name": "Ruby Security Guidelines",
          "description": "Comprehensive security guidelines for Ruby and Ruby on Rails"
        },
        {
          "@type": "SoftwareApplication",
          "name": "Node.js Security Guidelines",
          "description": "Security guidelines for Node.js and JavaScript applications"
        },
        {
          "@type": "SoftwareApplication",
          "name": "Java Security Guidelines",
          "description": "Security best practices for Java applications"
        },
        {
          "@type": "SoftwareApplication",
          "name": ".NET Security Guidelines",
          "description": "Security guidelines for .NET applications"
        }
      ]
    }
  };

  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
        />
      </head>
      <body>{children}</body>
    </html>
  )
}

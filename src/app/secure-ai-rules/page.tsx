import { Metadata } from 'next';
import dynamic from 'next/dynamic';

export const metadata: Metadata = {
  title: 'AI Security Rules & Guidelines - Browse Security Best Practices',
  description: 'Browse comprehensive AI security rules and guidelines for Angular, Python, Ruby, Node.js, Java, and .NET. Search and filter security best practices for building safe AI systems.',
  keywords: [
    'AI security rules',
    'AI security guidelines',
    'machine learning security',
    'secure AI development',
    'AI compliance rules',
    'Angular AI security',
    'Python AI security',
    'Ruby AI security',
    'Node.js AI security',
    'Java AI security',
    '.NET AI security',
    'AI security best practices',
    'secure coding guidelines'
  ],
  openGraph: {
    title: 'AI Security Rules & Guidelines - Browse Security Best Practices',
    description: 'Browse comprehensive AI security rules for Angular, Python, Ruby, Node.js, Java, and .NET. Search and filter security best practices.',
    url: 'https://secure-ai-dev.cycubix.com/secure-ai-rules',
  },
  twitter: {
    title: 'AI Security Rules & Guidelines - Browse Security Best Practices',
    description: 'Browse comprehensive AI security rules for Angular, Python, Ruby, Node.js, Java, and .NET.',
  },
  alternates: {
    canonical: 'https://secure-ai-dev.cycubix.com/secure-ai-rules',
  },
};

// Dynamically import the SecureAIDirectory component
const SecureAIDirectory = dynamic(
  () => import('../../components/SecureAIDirectory').then(mod => mod.default),
  {
    loading: () => (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-neutral-900 mx-auto"></div>
          <p className="mt-4 text-neutral-600">Loading rules directory...</p>
        </div>
      </div>
    )
  }
);

export default function SecureAIRulesPage() {
  return (
    <div className="min-h-screen">
      <SecureAIDirectory />
    </div>
  );
}

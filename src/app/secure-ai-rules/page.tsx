'use client';

import { Suspense } from 'react';
import dynamic from 'next/dynamic';

// Dynamically import the SecureAIDirectory component with no SSR
const SecureAIDirectory = dynamic(
  () => import('../../components/SecureAIDirectory').then(mod => mod.default),
  { 
    ssr: false,
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

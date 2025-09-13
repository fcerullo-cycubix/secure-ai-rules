"use client";

import { GlobeIcon, ShieldIcon, DatabaseIcon, WrenchIcon, HistoryIcon, BrainIcon } from "lucide-react";
import Link from "next/link";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-neutral-50 to-neutral-100">
      <main className="max-w-6xl mx-auto px-4 py-16">
        {/* Hero */}
        <div className="text-center mb-16">
          <h1 className="text-4xl font-bold mb-4">
            Secure AI Development Rules Directory
          </h1>
          <p className="text-xl text-neutral-600 mb-8">
            Comprehensive security guidelines for building safe, reliable, and compliant AI systems in 2025
          </p>
          <Link
            href="/secure-ai-rules"
            className="inline-flex items-center gap-2 px-6 py-3 text-lg font-medium text-white bg-neutral-900 rounded-xl hover:bg-neutral-800 transition-colors"
          >
            <ShieldIcon className="w-5 h-5" />
            Browse Security Rules
          </Link>
        </div>

        {/* Feature Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-16">
          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-blue-50 text-blue-600 rounded-xl">
              <ShieldIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Advanced Security</h3>
            <p className="text-neutral-600">
              Comprehensive defenses against prompt injection, data exfiltration, and emerging AI-specific threats.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-green-50 text-green-600 rounded-xl">
              <DatabaseIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Privacy Controls</h3>
            <p className="text-neutral-600">
              Robust data protection with advanced PII handling, retention policies, and compliance frameworks.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-purple-50 text-purple-600 rounded-xl">
              <WrenchIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Safe Tool Usage</h3>
            <p className="text-neutral-600">
              Secure patterns for AI agents, function calling, and third-party integrations with proper isolation.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-orange-50 text-orange-600 rounded-xl">
              <HistoryIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Incident Response</h3>
            <p className="text-neutral-600">
              Clear playbooks for AI-specific incidents with detection, containment, and recovery procedures.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-red-50 text-red-600 rounded-xl">
              <BrainIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Model Safety</h3>
            <p className="text-neutral-600">
              Best practices for model deployment, updates, and monitoring with comprehensive safety evaluations.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-yellow-50 text-yellow-600 rounded-xl">
              <GlobeIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Compliance Ready</h3>
            <p className="text-neutral-600">
              Built-in considerations for global AI regulations, data protection laws, and industry standards.
            </p>
          </div>
        </div>

        {/* CTA */}
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">
            Start Building Secure AI Systems Today
          </h2>
          <p className="text-neutral-600 mb-8">
            Access our comprehensive collection of security rules, best practices, and implementation guides.
          </p>
          <Link
            href="/secure-ai-rules"
            className="inline-flex items-center gap-2 px-6 py-3 text-lg font-medium text-white bg-neutral-900 rounded-xl hover:bg-neutral-800 transition-colors"
          >
            Get Started
          </Link>
        </div>
      </main>

      <footer className="border-t border-neutral-200 bg-white">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <p className="text-center text-sm text-neutral-600">
            Updated for 2025 • Covering latest AI security challenges • Regular updates based on industry developments
          </p>
        </div>
      </footer>
    </div>
  );
}

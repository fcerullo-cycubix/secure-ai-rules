"use client";

import { Code2Icon, ShieldIcon, LayersIcon, ServerIcon, CoffeeIcon, HashIcon } from "lucide-react";
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
            Framework-specific security guidelines for AI development across Angular, Python, Ruby, Node.js, Java, and .NET
          </p>
          <Link
            href="/secure-ai-rules"
            className="inline-flex items-center gap-2 px-6 py-3 text-lg font-medium text-white bg-neutral-900 rounded-xl hover:bg-neutral-800 transition-colors"
          >
            <ShieldIcon className="w-5 h-5" />
            Browse Security Rules
          </Link>
        </div>

        {/* Framework Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-16">
          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-red-50 text-red-600 rounded-xl">
              <LayersIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Angular Security</h3>
            <p className="text-neutral-600">
              Security best practices for Angular applications, including XSS prevention, authentication, and secure component patterns.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-blue-50 text-blue-600 rounded-xl">
              <Code2Icon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Python Security</h3>
            <p className="text-neutral-600">
              Comprehensive security guidelines for Python applications and AI/ML frameworks like TensorFlow and PyTorch.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-red-50 text-red-600 rounded-xl">
              <HashIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Ruby Security</h3>
            <p className="text-neutral-600">
              Security practices for Ruby and Ruby on Rails applications, covering input validation, authentication, and more.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-green-50 text-green-600 rounded-xl">
              <ServerIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Node.js Security</h3>
            <p className="text-neutral-600">
              Security guidelines for Node.js and JavaScript applications, including dependency management and runtime security.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-orange-50 text-orange-600 rounded-xl">
              <CoffeeIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Java Security</h3>
            <p className="text-neutral-600">
              Security best practices for Java applications, including secure coding patterns and framework-specific guidance.
            </p>
          </div>

          <div className="p-6 bg-white rounded-2xl border border-neutral-200 shadow-sm">
            <div className="w-12 h-12 mb-4 p-2.5 bg-purple-50 text-purple-600 rounded-xl">
              <ShieldIcon className="w-full h-full" />
            </div>
            <h3 className="text-lg font-semibold mb-2">.NET Security</h3>
            <p className="text-neutral-600">
              Security guidelines for .NET applications, covering ASP.NET Core, Entity Framework, and secure deployment practices.
            </p>
          </div>
        </div>

        {/* CTA */}
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">
            Secure Your AI Development Stack
          </h2>
          <p className="text-neutral-600 mb-8">
            Framework-specific security guidelines for Angular, Python, Ruby, Node.js, Java, and .NET applications.
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
            Framework-specific security guidelines • Updated for 2025 • Covering Angular, Python, Ruby, Node.js, Java & .NET
          </p>
        </div>
      </footer>
    </div>
  );
}

"use client";

import React, { useMemo, useState } from "react";
import { Search, Shield, Copy, ChevronDown, ChevronUp, Filter, BadgeCheck, Lock } from "lucide-react";
import { rules } from "../rules";

export type Rule = {
  id: string;
  title: string;
  summary: string;
  body: string;
  tags: string[];
};

const RULES = rules || [];
const ALL_TAGS = Array.from(new Set(RULES.filter(r => r && r.tags).flatMap(r => r.tags))).sort();

export default function SecureAIDirectory() {
  const [query, setQuery] = useState("");
  const [activeTags, setActiveTags] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return RULES.filter(r => {
      const matchesQ = !q ||
        r.title.toLowerCase().includes(q) ||
        r.summary.toLowerCase().includes(q) ||
        r.body.toLowerCase().includes(q) ||
        r.tags.some(t => t.toLowerCase().includes(q));
      const matchesTags = activeTags.length === 0 || activeTags.every(t => r.tags.includes(t));
      return matchesQ && matchesTags;
    });
  }, [query, activeTags]);

  const handleToggleTag = (tag: string) => {
    setActiveTags(prev => prev.includes(tag) ? prev.filter(t => t !== tag) : [...prev, tag]);
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      alert("Copied to clipboard");
    } catch {
      alert("Copy failed. Select and copy manually.");
    }
  };

  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900">
      {/* Top Nav */}
      <header className="sticky top-0 z-10 bg-white/80 backdrop-blur border-b border-neutral-200">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <Shield className="w-6 h-6" aria-hidden />
          <h1 className="text-xl font-semibold">Secure Development with AI — Rules Directory</h1>
          <span className="ml-auto text-sm text-neutral-500">{RULES.length} rules</span>
        </div>
      </header>

      {/* Controls */}
      <section className="max-w-6xl mx-auto px-4 py-4">
        <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search rules, e.g. 'prompt injection', 'RAG', 'logging'…"
              className="w-full pl-9 pr-3 py-2 rounded-xl border border-neutral-300 focus:outline-none focus:ring-2 focus:ring-neutral-800"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Filter className="w-4 h-4" />
            {ALL_TAGS.map(tag => (
              <button
                key={tag}
                onClick={() => handleToggleTag(tag)}
                className={`px-3 py-1 rounded-full text-sm border ${activeTags.includes(tag) ? "bg-neutral-900 text-white border-neutral-900" : "bg-white border-neutral-300"}`}
              >
                {tag}
              </button>
            ))}
            {activeTags.length > 0 && (
              <button
                onClick={() => setActiveTags([])}
                className="px-3 py-1 rounded-full text-sm border bg-white border-neutral-300"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </section>

      {/* List */}
      <main className="max-w-6xl mx-auto px-4 pb-12">
        <div className="grid grid-cols-1 gap-4">
          {filtered.map(rule => {
            const isOpen = !!expanded[rule.id];
            return (
              <article key={rule.id} className="bg-white border border-neutral-200 rounded-2xl shadow-sm">
                <div className="p-4 flex items-start gap-3">
                  <div className="mt-1">
                    <Lock className="w-5 h-5" aria-hidden />
                  </div>
                  <div className="flex-1">
                    <h2 className="text-lg font-semibold leading-snug">{rule.title}</h2>
                    <p className="text-sm text-neutral-600 mt-1">{rule.summary}</p>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {rule.tags?.map(t => (
                        <span key={t} className="text-xs px-2 py-0.5 rounded-full bg-neutral-100 border border-neutral-200">{t}</span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(rule.body)}
                      className="inline-flex items-center gap-1 text-sm px-3 py-1.5 rounded-lg border border-neutral-300 hover:bg-neutral-50"
                      aria-label="Copy rule body"
                    >
                      <Copy className="w-4 h-4" /> Copy
                    </button>
                    <button
                      onClick={() => setExpanded(prev => ({ ...prev, [rule.id]: !isOpen }))}
                      className="inline-flex items-center gap-1 text-sm px-3 py-1.5 rounded-lg border border-neutral-300 hover:bg-neutral-50"
                      aria-expanded={isOpen}
                      aria-controls={`section-${rule.id}`}
                    >
                      {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />} Details
                    </button>
                  </div>
                </div>
                {isOpen && (
                  <div id={`section-${rule.id}`} className="px-4 pb-4">
                    <pre className="whitespace-pre-wrap text-sm bg-neutral-50 border border-neutral-200 rounded-xl p-4 overflow-x-auto">
                      {rule.body}
                    </pre>
                  </div>
                )}
              </article>
            );
          })}

          {filtered.length === 0 && (
            <div className="text-center text-neutral-500 py-16">
              <BadgeCheck className="w-8 h-8 mx-auto mb-2" />
              <p>No rules match your search/filters.</p>
            </div>
          )}
        </div>
      </main>

      <footer className="max-w-6xl mx-auto px-4 pb-10 text-sm text-neutral-500">
        <p>
          Starter directory for AI-secure development rules. Customize titles, bodies, and tags to match your org. Add
          more rules in <code>RULES[]</code> and extend with export/share actions.
        </p>
      </footer>
    </div>
  );
}

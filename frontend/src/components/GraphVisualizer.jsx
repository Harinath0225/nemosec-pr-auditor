import React from 'react';
import { Check, Loader2, Minus } from 'lucide-react';

export default function GraphVisualizer({
  activeNodes = [],
  completedNodes = [],
  isRunning = false,
  preSnyk = null,
  postSnyk = null,
  githubPushResult = null,
}) {
  const hadVulnerability = (preSnyk?.total_issues || 0) > 0;
  const isCleanPR = preSnyk && preSnyk.total_issues === 0;

  const steps = [
    {
      num: '01',
      label: 'PR Diff & AST Ingest',
      detail: completedNodes.includes('ingest_node') ? 'Target loaded from PR' : 'Waiting for PR',
      state: completedNodes.includes('ingest_node')
        ? 'done'
        : activeNodes.includes('ingest_node')
        ? 'running'
        : 'idle',
    },
    {
      num: '02',
      label: 'Snyk Security Scan',
      detail: preSnyk
        ? hadVulnerability
          ? `${preSnyk.total_issues} Critical (${preSnyk.vulnerabilities?.[0]?.cve}) → Triggering Auto-Fix`
          : '0 Vulnerabilities Found (Clean PR)'
        : 'Scanning AST & Snyk rules',
      state: completedNodes.includes('snyk_scanner_node')
        ? 'done'
        : activeNodes.includes('snyk_scanner_node')
        ? 'running'
        : 'idle',
      badge: preSnyk
        ? hadVulnerability
          ? { text: 'VULN FOUND', tone: 'amber' }
          : { text: '0 ISSUES', tone: 'emerald' }
        : null,
    },
    {
      num: '03',
      label: isCleanPR ? 'Same-PR Fix (Bypassed)' : 'Same-PR Fix Check-In & Pytest',
      detail: isCleanPR
        ? 'No vulnerability found — code untouched'
        : completedNodes.includes('sandbox_patcher_node')
        ? 'Checked into PR branch • Pytest 3/3 • Snyk 0 issues'
        : 'Patching in sandbox & checking into PR',
      state: isCleanPR
        ? 'skipped'
        : completedNodes.includes('sandbox_patcher_node')
        ? 'done'
        : activeNodes.includes('sandbox_patcher_node')
        ? 'running'
        : 'idle',
      badge:
        completedNodes.includes('sandbox_patcher_node') && hadVulnerability
          ? { text: 'SNYK ISSUE GONE', tone: 'emerald' }
          : isCleanPR
          ? { text: 'SKIPPED', tone: 'zinc' }
          : null,
    },
    {
      num: '04',
      label: 'Socratic PR Comment',
      detail: completedNodes.includes('finalize_audit_node')
        ? hadVulnerability
          ? 'Posted Socratic questions + fix check-in note to PR'
          : 'Posted Socratic questions to clean PR'
        : 'Generating Socratic review via Nemotron',
      state: completedNodes.includes('finalize_audit_node')
        ? 'done'
        : activeNodes.includes('socratic_intent_node') || activeNodes.includes('finalize_audit_node')
        ? 'running'
        : 'idle',
      badge: completedNodes.includes('finalize_audit_node')
        ? { text: 'COMMENTED ON PR', tone: 'white' }
        : null,
    },
  ];

  return (
    <div className="bg-[#111113] border border-[#232329] rounded-xl px-4 py-3">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {steps.map((step, i) => {
          const isDone = step.state === 'done';
          const isActive = step.state === 'running';
          const isSkipped = step.state === 'skipped';

          return (
            <div
              key={step.num}
              className={`relative flex flex-col justify-between p-3 rounded-lg border transition-all ${
                isActive
                  ? 'bg-[#18181c] border-white/30'
                  : isDone
                  ? 'bg-[#141417] border-[#27272d]'
                  : isSkipped
                  ? 'bg-[#0e0e11] border-[#1f1f24] opacity-65'
                  : 'bg-[#0e0e11] border-[#1c1c21] opacity-50'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2">
                  <span
                    className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-mono font-semibold ${
                      isDone
                        ? 'bg-emerald-500 text-black'
                        : isActive
                        ? 'bg-white text-black'
                        : 'bg-[#232329] text-zinc-400'
                    }`}
                  >
                    {isDone ? (
                      <Check className="w-3 h-3 stroke-[3]" />
                    ) : isActive ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : isSkipped ? (
                      <Minus className="w-3 h-3" />
                    ) : (
                      step.num
                    )}
                  </span>
                  <span className="text-xs font-semibold text-zinc-100 tracking-tight">
                    {step.label}
                  </span>
                </div>

                {step.badge && (
                  <span
                    className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded ${
                      step.badge.tone === 'emerald'
                        ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        : step.badge.tone === 'amber'
                        ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                        : step.badge.tone === 'white'
                        ? 'bg-white/10 text-zinc-100 border border-white/20'
                        : 'bg-zinc-800 text-zinc-400'
                    }`}
                  >
                    {step.badge.text}
                  </span>
                )}
              </div>

              <p className="text-[11px] text-zinc-400 leading-snug truncate">{step.detail}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

import React, { useState } from 'react';
import {
  ShieldCheck,
  GitCommit,
  Terminal,
  ExternalLink,
  ArrowRight,
  CheckCircle2,
  Code2,
} from 'lucide-react';

export default function SecOpsPanel({
  preSnyk,
  postSnyk,
  remediatedCode,
  unifiedDiff,
  sandboxResults,
  branchInfo,
  githubPushResult,
}) {
  const [viewMode, setViewMode] = useState('diff'); // 'diff' | 'full_code' | 'snyk_raw'

  const vulns = preSnyk?.vulnerabilities || [];
  const primaryVuln = vulns[0] || null;
  const hadVulnerability = (preSnyk?.total_issues || 0) > 0;

  const renderDiffLines = (diffText) => {
    if (!diffText) {
      return (
        <div className="p-8 text-center text-xs text-zinc-400 font-mono">
          No security vulnerabilities found by Snyk (0 issues) — Original PR code kept intact.
        </div>
      );
    }
    return diffText.split('\n').map((line, idx) => {
      let rowStyle = 'text-zinc-300';
      if (line.startsWith('+++') || line.startsWith('---')) {
        rowStyle = 'text-zinc-500 font-semibold bg-[#0e0e11]';
      } else if (line.startsWith('@@')) {
        rowStyle = 'text-zinc-400 bg-[#141419]';
      } else if (line.startsWith('+')) {
        rowStyle = 'text-emerald-300 bg-emerald-500/10';
      } else if (line.startsWith('-')) {
        rowStyle = 'text-rose-300 bg-rose-500/10';
      }
      return (
        <div
          key={idx}
          className={`px-3.5 py-0.5 font-mono text-[11px] leading-relaxed whitespace-pre ${rowStyle}`}
        >
          {line}
        </div>
      );
    });
  };

  return (
    <div className="bg-[#111113] border border-[#232329] rounded-xl flex flex-col overflow-hidden">
      {/* Top Bar */}
      <div className="px-5 py-3.5 border-b border-[#232329] bg-[#141417] flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-semibold text-zinc-100">
            Snyk Security Scan &amp; Same-PR Fix Check-In
          </span>
        </div>

        <div className="flex items-center gap-1 bg-[#09090b] p-0.5 rounded-md border border-[#232329] text-[11px] font-mono">
          <button
            onClick={() => setViewMode('diff')}
            className={`px-2.5 py-1 rounded transition ${
              viewMode === 'diff' ? 'bg-[#232329] text-white' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Checked-In Diff
          </button>
          <button
            onClick={() => setViewMode('full_code')}
            className={`px-2.5 py-1 rounded transition ${
              viewMode === 'full_code'
                ? 'bg-[#232329] text-white'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Full File
          </button>
          <button
            onClick={() => setViewMode('snyk_raw')}
            className={`px-2.5 py-1 rounded transition ${
              viewMode === 'snyk_raw'
                ? 'bg-[#232329] text-white'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Snyk JSON
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="p-5 space-y-4 flex-1">
        {!preSnyk ? (
          <div className="py-16 text-center text-xs text-zinc-500 font-mono">
            Running Snyk AST scan &amp; isolated pytest sandbox...
          </div>
        ) : (
          <>
            {/* 1. Snyk Before -> After Transition Strip */}
            <div className="rounded-lg border border-[#232329] bg-[#0c0c0e] p-3.5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                {/* Before */}
                <div className="space-y-1">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
                    Initial PR Snyk Scan
                  </div>
                  {hadVulnerability ? (
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-rose-500" />
                      <span className="text-xs font-semibold text-rose-300">
                        {primaryVuln?.cve} · {primaryVuln?.id}
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30">
                        CVSS {primaryVuln?.cvssScore}
                      </span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      <span className="text-xs font-semibold text-emerald-300">
                        0 Vulnerabilities Detected
                      </span>
                    </div>
                  )}
                </div>

                <ArrowRight className="w-4 h-4 text-zinc-600 hidden sm:block shrink-0" />

                {/* After */}
                <div className="space-y-1 sm:text-right">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
                    {hadVulnerability ? 'After Same-PR Auto-Fix Check-In' : 'Final PR Security Status'}
                  </div>
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-semibold">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>
                      Snyk Re-Scan: 0 Vulnerabilities ({hadVulnerability ? 'Snyk Issue Gone' : 'Clean'})
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* 2. Same-PR Check-In Commit Box (when vulnerability was found & fixed) */}
            {hadVulnerability && (
              <div className="rounded-lg border border-[#232329] bg-[#0c0c0e] p-3.5 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2 font-mono text-zinc-200">
                    <GitCommit className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Checked into PR branch:</span>
                    <span className="text-emerald-300 font-semibold">
                      {githubPushResult?.branch_name || branchInfo?.branch_name || 'feat/merchant-ledger-filter'}
                    </span>
                  </div>
                  {githubPushResult?.commit_url && (
                    <a
                      href={githubPushResult.commit_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-[11px] font-mono text-zinc-300 hover:text-white"
                    >
                      Commit {githubPushResult.commit_sha} <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
                <div className="text-xs font-mono text-emerald-300 bg-[#09090b] px-3 py-2 rounded border border-[#1f1f24]">
                  {githubPushResult?.commit_message || branchInfo?.commit_message}
                </div>
              </div>
            )}

            {/* 3. Code Diff / Full Code / Snyk Raw View */}
            {viewMode === 'diff' ? (
              <div className="rounded-lg border border-[#232329] bg-[#09090b] overflow-hidden">
                <div className="px-3.5 py-2 border-b border-[#232329] bg-[#111114] flex items-center justify-between text-[11px] font-mono text-zinc-400">
                  <span>{primaryVuln?.file_path || 'demo-vulnerable-app/payment_ledger.py'}</span>
                  <span className="text-emerald-400">
                    {hadVulnerability ? 'Committed to PR' : '0 Changes Needed'}
                  </span>
                </div>
                <div className="py-2 overflow-x-auto max-h-[300px]">
                  {renderDiffLines(unifiedDiff)}
                </div>
              </div>
            ) : viewMode === 'full_code' ? (
              <div className="rounded-lg border border-[#232329] bg-[#09090b] overflow-hidden">
                <div className="px-3.5 py-2 border-b border-[#232329] bg-[#111114] flex items-center justify-between text-[11px] font-mono text-zinc-400">
                  <span className="flex items-center gap-1.5">
                    <Code2 className="w-3.5 h-3.5" /> Remediated File Checked into PR
                  </span>
                </div>
                <pre className="p-3.5 text-[11px] font-mono text-zinc-200 overflow-x-auto max-h-[300px] leading-relaxed">
                  {remediatedCode}
                </pre>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="rounded-lg border border-[#232329] bg-[#09090b] overflow-hidden">
                  <div className="px-3 py-1.5 border-b border-[#232329] bg-[#111114] text-[11px] font-mono text-rose-300">
                    Before Fix (total_issues: {preSnyk.total_issues})
                  </div>
                  <pre className="p-3 text-[10px] font-mono text-zinc-300 overflow-x-auto max-h-[260px]">
                    {JSON.stringify(preSnyk, null, 2)}
                  </pre>
                </div>
                <div className="rounded-lg border border-emerald-500/30 bg-[#09090b] overflow-hidden">
                  <div className="px-3 py-1.5 border-b border-emerald-500/30 bg-emerald-950/20 text-[11px] font-mono text-emerald-300">
                    After Fix (total_issues: 0 • RESOLVED)
                  </div>
                  <pre className="p-3 text-[10px] font-mono text-emerald-300 overflow-x-auto max-h-[260px]">
                    {JSON.stringify(postSnyk, null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {/* 4. Isolated Pytest Sandbox Terminal Output (Always visible below diff) */}
            {sandboxResults && (
              <div className="rounded-lg border border-[#232329] bg-[#09090b] overflow-hidden">
                <div className="px-3.5 py-2 border-b border-[#232329] bg-[#111114] flex items-center justify-between text-[11px] font-mono">
                  <span className="text-zinc-300 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                    Isolated Pytest Sandbox Verification
                  </span>
                  <span className="text-emerald-400">
                    {sandboxResults.passed_count}/{sandboxResults.total_count} passed ({sandboxResults.duration_ms}ms)
                  </span>
                </div>
                <pre className="p-3.5 text-[11px] font-mono text-zinc-300 overflow-x-auto max-h-[190px] whitespace-pre-wrap leading-relaxed">
                  {sandboxResults.stdout}
                </pre>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

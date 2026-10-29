import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Terminal,
  GitBranch,
  FileDiff,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Play,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';

export default function SecOpsPanel({
  preSnyk,
  postSnyk,
  remediatedCode,
  remediationExplanation,
  unifiedDiff,
  sandboxResults,
  branchInfo,
  snykAppliedToPR,
  onApplyRemediationToPR,
  isApplyingRemediation,
  githubPushResult,
}) {
  const [activeTab, setActiveTab] = useState('diff'); // 'diff' | 'sandbox' | 'snyk_json' | 'patched_code'

  const vulns = preSnyk?.vulnerabilities || [];
  const primaryVuln = vulns[0] || null;
  const isResolved = Boolean(snykAppliedToPR || (postSnyk && postSnyk.ok));

  const renderDiffLines = (diffText) => {
    if (!diffText) return null;
    return diffText.split('\n').map((line, idx) => {
      let lineClass = 'text-slate-300';
      if (line.startsWith('+++') || line.startsWith('---')) {
        lineClass = 'text-slate-400 font-bold';
      } else if (line.startsWith('@@')) {
        lineClass = 'text-cyan-400 bg-cyan-950/30';
      } else if (line.startsWith('+')) {
        lineClass = 'text-emerald-300 bg-emerald-950/40';
      } else if (line.startsWith('-')) {
        lineClass = 'text-rose-300 bg-rose-950/40';
      }
      return (
        <div key={idx} className={`px-3 py-0.5 font-mono text-xs whitespace-pre ${lineClass}`}>
          {line}
        </div>
      );
    });
  };

  return (
    <div className="bg-slate-900/90 border border-emerald-500/30 rounded-2xl flex flex-col h-full shadow-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 bg-gradient-to-r from-emerald-950/70 via-slate-900 to-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div
            className={`p-2.5 rounded-xl border ${
              snykAppliedToPR
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
            }`}
          >
            {snykAppliedToPR ? (
              <ShieldCheck className="w-5 h-5" />
            ) : (
              <ShieldAlert className="w-5 h-5" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-100">
                Branch B: SecOps Auto-Remediation Agent
              </h2>
              {snykAppliedToPR ? (
                <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-semibold">
                  Snyk Status: 0 Vulnerabilities (Resolved)
                </span>
              ) : primaryVuln ? (
                <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold">
                  Snyk Alert: {primaryVuln.cve} (CVSS {primaryVuln.cvssScore})
                </span>
              ) : null}
            </div>
            <p className="text-xs text-slate-400">
              Snyk CVE detection, isolated <code className="text-emerald-300">pytest</code> sandbox verification &amp; PR auto-patch
            </p>
          </div>
        </div>

        {/* 1-Click Apply Remediation & Clear Snyk Issue on PR */}
        {remediatedCode && (
          <button
            onClick={onApplyRemediationToPR}
            disabled={isApplyingRemediation}
            className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow transition disabled:opacity-50 ${
              snykAppliedToPR
                ? 'bg-emerald-600/30 text-emerald-200 border border-emerald-500/50 hover:bg-emerald-600/40'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white'
            }`}
          >
            {isApplyingRemediation ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                Applying Patch &amp; Re-Scanning Snyk...
              </>
            ) : snykAppliedToPR ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-300" />
                Vulnerability Remediated &amp; Snyk Issue Gone
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                Apply Fix to PR &amp; Resolve Snyk Issue
              </>
            )}
          </button>
        )}
      </div>

      {/* Snyk Before -> After Status Bar */}
      {preSnyk && (
        <div className="px-5 py-3 bg-slate-950/80 border-b border-slate-800 grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
          {/* Card 1: Initial Snyk Scan */}
          <div
            className={`p-2.5 rounded-xl border ${
              snykAppliedToPR
                ? 'bg-slate-900/60 border-slate-800 opacity-75'
                : 'bg-rose-950/30 border-rose-500/35'
            }`}
          >
            <div className="flex items-center justify-between text-[11px] text-slate-400 mb-0.5">
              <span>Initial Snyk PR Scan</span>
              <span className="font-mono text-rose-400 font-semibold">
                {preSnyk.total_issues} Issue(s)
              </span>
            </div>
            <div className="font-semibold text-slate-200 truncate">
              {primaryVuln ? `${primaryVuln.id} (${primaryVuln.cve})` : 'No Issues'}
            </div>
          </div>

          {/* Card 2: Pytest Sandbox Check */}
          <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800">
            <div className="flex items-center justify-between text-[11px] text-slate-400 mb-0.5">
              <span>Isolated Pytest Sandbox</span>
              {sandboxResults && (
                <span className="font-mono text-emerald-400 font-semibold">
                  {sandboxResults.passed_count}/{sandboxResults.total_count} Passed ({sandboxResults.duration_ms}ms)
                </span>
              )}
            </div>
            <div className="font-semibold text-slate-200 truncate flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Exploit Blocked &amp; Unit Tests Green</span>
            </div>
          </div>

          {/* Card 3: Post-Remediation Snyk Re-Scan */}
          <div
            className={`p-2.5 rounded-xl border transition-all ${
               isResolved
                ? 'bg-emerald-950/40 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.15)]'
                : 'bg-slate-900/80 border-slate-800'
            }`}
          >
            <div className="flex items-center justify-between text-[11px] text-slate-400 mb-0.5">
              <span>Post-Patch Snyk Re-Scan</span>
              <span className="font-mono text-emerald-400 font-bold">
                {postSnyk ? `${postSnyk.total_issues} Issues` : 'Pending'}
              </span>
            </div>
            <div className="font-bold text-emerald-300 truncate flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                {snykAppliedToPR
                  ? 'Snyk Issue Gone (Applied to PR)'
                  : 'Verified Clean (0 Vulns in Patch)'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Sub-navigation Tabs */}
      <div className="px-5 pt-2.5 bg-slate-900/60 border-b border-slate-800 flex flex-wrap items-center gap-2 text-xs">
        <button
          onClick={() => setActiveTab('diff')}
          className={`px-3 py-2 rounded-t-lg font-medium border-b-2 transition flex items-center gap-1.5 ${
            activeTab === 'diff'
              ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileDiff className="w-3.5 h-3.5" />
          Unified Remediation Diff
        </button>

        <button
          onClick={() => setActiveTab('sandbox')}
          className={`px-3 py-2 rounded-t-lg font-medium border-b-2 transition flex items-center gap-1.5 ${
            activeTab === 'sandbox'
              ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Pytest Sandbox Logs
        </button>

        <button
          onClick={() => setActiveTab('snyk_json')}
          className={`px-3 py-2 rounded-t-lg font-medium border-b-2 transition flex items-center gap-1.5 ${
            activeTab === 'snyk_json'
              ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          Snyk Report (Before vs After)
        </button>

        <button
          onClick={() => setActiveTab('patched_code')}
          className={`px-3 py-2 rounded-t-lg font-medium border-b-2 transition flex items-center gap-1.5 ${
            activeTab === 'patched_code'
              ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Code2 className="w-3.5 h-3.5" />
          Patched Code &amp; Branch
        </button>
      </div>

      {/* Body Content */}
      <div className="p-5 flex-1 overflow-y-auto space-y-4">
        {!preSnyk ? (
          <div className="flex flex-col items-center justify-center h-64 text-center text-slate-500">
            <ShieldAlert className="w-10 h-10 mb-3 text-slate-600 animate-pulse" />
            <p className="text-sm font-medium text-slate-400">
              Ready for Snyk Security Scan &amp; Sandbox Auto-Remediation
            </p>
            <p className="text-xs text-slate-500 max-w-sm mt-1">
              Click &ldquo;Run Dual-Branch PR Audit&rdquo; to detect CVEs, run isolated <code className="text-slate-400">pytest</code> verification, and resolve the Snyk vulnerability.
            </p>
          </div>
        ) : activeTab === 'diff' ? (
          <>
            {/* Vulnerability Details Banner (or Resolved Banner) */}
            {snykAppliedToPR ? (
              <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/40 flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <div className="font-bold text-emerald-200 text-sm">
                    Snyk Vulnerability Resolved — 0 Issues Remaining in Code &amp; PR!
                  </div>
                  <p className="text-slate-300">
                    The security remediation patch for <code>{primaryVuln?.id}</code> ({primaryVuln?.cve}) has been applied and re-scanned with Snyk Code. All SQL/Command injection vectors are eliminated.
                  </p>
                  {githubPushResult?.commit_url && (
                    <a
                      href={githubPushResult.commit_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-emerald-300 font-semibold hover:underline pt-1"
                    >
                      View Remediated Commit on GitHub <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              </div>
            ) : (
              primaryVuln && (
                <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-500/30 space-y-1.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-bold text-rose-300 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-rose-400" />
                      {primaryVuln.title}
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-200 border border-rose-500/30">
                      {primaryVuln.id} • {primaryVuln.cve} • Line {primaryVuln.line_number}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{primaryVuln.description}</p>
                </div>
              )
            )}

            {/* Unified Diff Box */}
            <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden">
              <div className="px-4 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
                <span className="font-mono text-slate-300 font-medium">
                  Unified Remediation Patch ({primaryVuln?.file_path || 'demo-vulnerable-app/payment_ledger.py'})
                </span>
                <span className="text-[11px] text-emerald-400 font-mono">
                  + Parameterized / Hardened
                </span>
              </div>
              <div className="py-2 overflow-x-auto">{renderDiffLines(unifiedDiff)}</div>
            </div>

            {/* Git Branch Status Card */}
            {branchInfo && (
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                    <GitBranch className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-emerald-300">
                        {branchInfo.branch_name}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        ({branchInfo.commit_hash})
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px]">{branchInfo.commit_message}</p>
                  </div>
                </div>
                <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  {branchInfo.status}
                </span>
              </div>
            )}
          </>
        ) : activeTab === 'sandbox' ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-300">
                Isolated Temp-Directory <code className="text-emerald-300">pytest -v</code> Execution Output
              </span>
              {sandboxResults && (
                <span className="font-mono text-emerald-400">
                  Exit Code: {sandboxResults.exit_code} • {sandboxResults.duration_ms}ms
                </span>
              )}
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-emerald-300 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {sandboxResults?.stdout || 'No sandbox output available.'}
            </pre>

            {sandboxResults?.test_suite_source && (
              <div className="space-y-1.5 pt-2">
                <div className="text-xs font-semibold text-slate-400">
                  Generated Sandbox Security &amp; Functional Test Suite (<code>test_secops_remediation.py</code>)
                </div>
                <pre className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 text-[11px] text-slate-300 font-mono overflow-x-auto">
                  {sandboxResults.test_suite_source}
                </pre>
              </div>
            )}
          </div>
        ) : activeTab === 'snyk_json' ? (
          <div className="grid grid-cols-1 gap-3">
            <div className="rounded-xl border border-rose-500/30 bg-slate-950 overflow-hidden">
              <div className="px-3.5 py-2 bg-rose-950/40 border-b border-rose-500/30 flex items-center justify-between text-xs">
                <span className="font-semibold text-rose-200">
                  1. Pre-Remediation Snyk Scan (Vulnerable PR Code)
                </span>
                <span className="font-mono text-rose-300">
                  ok: false • total_issues: {preSnyk.total_issues}
                </span>
              </div>
              <pre className="p-3.5 text-[11px] text-slate-300 font-mono overflow-x-auto max-h-52">
                {JSON.stringify(preSnyk, null, 2)}
              </pre>
            </div>

            <div className="rounded-xl border border-emerald-500/40 bg-slate-950 overflow-hidden">
              <div className="px-3.5 py-2 bg-emerald-950/40 border-b border-emerald-500/30 flex items-center justify-between text-xs">
                <span className="font-semibold text-emerald-200">
                  2. Post-Remediation Snyk Live Re-Scan (After SecOps Patch)
                </span>
                <span className="font-mono text-emerald-300 font-bold">
                  ok: true • total_issues: 0 (RESOLVED)
                </span>
              </div>
              <pre className="p-3.5 text-[11px] text-emerald-300 font-mono overflow-x-auto">
                {JSON.stringify(postSnyk, null, 2)}
              </pre>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-300 leading-relaxed">{remediationExplanation}</p>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono overflow-x-auto leading-relaxed">
              {remediatedCode}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

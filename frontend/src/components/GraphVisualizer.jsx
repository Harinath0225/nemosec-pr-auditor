import React from 'react';
import {
  GitPullRequest,
  BrainCircuit,
  ShieldAlert,
  TerminalSquare,
  CheckCircle2,
  Loader2,
  CircleDot,
  Sparkles,
} from 'lucide-react';

const NODES = [
  {
    id: 'ingest_node',
    title: 'PR & Diff Ingest',
    subtitle: 'GitHub PR + AST Context',
    branch: 'core',
    icon: GitPullRequest,
  },
  {
    id: 'socratic_intent_node',
    title: 'Branch A: Socratic Agent',
    subtitle: 'Questions + PR Comment + Changelog',
    branch: 'branch_a',
    icon: BrainCircuit,
  },
  {
    id: 'snyk_scanner_node',
    title: 'Branch B1: Snyk Scanner',
    subtitle: 'Live AST + Snyk JSON CVE Parse',
    branch: 'branch_b',
    icon: ShieldAlert,
  },
  {
    id: 'sandbox_patcher_node',
    title: 'Branch B2: Pytest Sandbox',
    subtitle: 'Auto-Patch + Pytest + Snyk Re-Scan',
    branch: 'branch_b',
    icon: TerminalSquare,
  },
  {
    id: 'finalize_audit_node',
    title: 'Audit Convergence',
    subtitle: 'PR Commented & Snyk 0 Issues',
    branch: 'core',
    icon: Sparkles,
  },
];

export default function GraphVisualizer({ activeNodes = [], completedNodes = [], isRunning = false, snykResolved = false }) {
  const getNodeStatus = (nodeId) => {
    if (completedNodes.includes(nodeId)) return 'completed';
    if (activeNodes.includes(nodeId)) return 'active';
    return 'idle';
  };

  const renderNodeCard = (node) => {
    const status = getNodeStatus(node.id);
    const Icon = node.icon;

    const borderClass =
      status === 'active'
        ? 'border-amber-400/90 bg-amber-500/10 shadow-[0_0_20px_rgba(251,191,36,0.25)]'
        : status === 'completed'
        ? node.branch === 'branch_a'
          ? 'border-indigo-500/70 bg-indigo-950/40'
          : node.branch === 'branch_b'
          ? 'border-emerald-500/70 bg-emerald-950/40'
          : 'border-cyan-500/70 bg-cyan-950/30'
        : 'border-slate-800 bg-slate-900/60 opacity-75';

    return (
      <div
        key={node.id}
        className={`relative flex items-center gap-3 px-3.5 py-2.5 rounded-xl border transition-all duration-300 min-w-[205px] ${borderClass}`}
      >
        <div
          className={`p-2 rounded-lg ${
            status === 'active'
              ? 'bg-amber-500/20 text-amber-300 animate-pulse'
              : status === 'completed'
              ? node.branch === 'branch_a'
                ? 'bg-indigo-500/20 text-indigo-300'
                : 'bg-emerald-500/20 text-emerald-300'
              : 'bg-slate-800 text-slate-400'
          }`}
        >
          <Icon className="w-4 h-4" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-1.5">
            <span className="text-xs font-semibold text-slate-100 truncate">{node.title}</span>
            {status === 'active' && <Loader2 className="w-3.5 h-3.5 text-amber-400 animate-spin shrink-0" />}
            {status === 'completed' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
            {status === 'idle' && <CircleDot className="w-3.5 h-3.5 text-slate-600 shrink-0" />}
          </div>
          <p className="text-[11px] text-slate-400 truncate">{node.subtitle}</p>
        </div>
      </div>
    );
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800/90 rounded-2xl p-4 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
            LangGraph Parallel StateGraph
          </span>
          <span className="text-xs text-slate-400">
            Real-time SSE execution topology — Dual-Branch Socratic & SecOps Remediation
          </span>
        </div>

        <div className="flex items-center gap-3 text-xs">
          {isRunning && (
            <span className="inline-flex items-center gap-1.5 text-amber-300 font-medium">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Streaming LangGraph nodes...
            </span>
          )}
          {snykResolved && !isRunning && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Snyk Re-Scan: 0 Vulnerabilities
            </span>
          )}
        </div>
      </div>

      {/* Responsive Parallel DAG Layout */}
      <div className="flex flex-col lg:flex-row items-center justify-between gap-3 overflow-x-auto py-1">
        {/* Step 1: Ingest */}
        {renderNodeCard(NODES[0])}

        <div className="hidden lg:flex items-center text-slate-600 font-mono text-xs">══╦══►</div>

        {/* Step 2: Parallel Branches A & B */}
        <div className="flex flex-col gap-2.5 w-full lg:w-auto">
          {/* Branch A */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 shrink-0">
              Branch A
            </span>
            {renderNodeCard(NODES[1])}
          </div>

          {/* Branch B */}
          <div className="flex flex-wrap sm:flex-nowrap items-center gap-2">
            <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shrink-0">
              Branch B
            </span>
            {renderNodeCard(NODES[2])}
            <span className="text-slate-500 font-mono text-xs hidden sm:inline">──►</span>
            {renderNodeCard(NODES[3])}
          </div>
        </div>

        <div className="hidden lg:flex items-center text-slate-600 font-mono text-xs">══╩══►</div>

        {/* Step 3: Convergence */}
        {renderNodeCard(NODES[4])}
      </div>
    </div>
  );
}

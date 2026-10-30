import React, { useState } from 'react';
import {
  GitCommit,
  ExternalLink,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Send,
  ShieldCheck,
  MessageSquare,
} from 'lucide-react';

export default function SocraticPanel({
  socraticAnalysis,
  prUrl,
  prCommentResult,
  githubPushResult,
  preSnyk,
  onPostCommentToPR,
  isPostingComment,
}) {
  const [expandedInsight, setExpandedInsight] = useState({});
  const [showChangelog, setShowChangelog] = useState(false);
  const [developerAnswers, setDeveloperAnswers] = useState({});
  const [copiedDoc, setCopiedDoc] = useState(false);

  const questions = socraticAnalysis?.questions || [];
  const tradeoffs = socraticAnalysis?.architectural_tradeoffs || [];
  const summary = socraticAnalysis?.summary || '';
  const prIntentMarkdown = socraticAnalysis?.pr_intent_markdown || '';
  const hadVulnerability = (preSnyk?.total_issues || 0) > 0;

  const toggleInsight = (id) => {
    setExpandedInsight((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyDoc = () => {
    navigator.clipboard.writeText(prIntentMarkdown);
    setCopiedDoc(true);
    setTimeout(() => setCopiedDoc(false), 2000);
  };

  const buildCombinedCommentBody = () => {
    const baseComment = prCommentResult?.body || socraticAnalysis?.formatted_pr_comment || '';
    const answeredEntries = questions
      .filter((q) => (developerAnswers[q.id] || '').trim().length > 0)
      .map(
        (q, i) =>
          `- **Q${i + 1} (${q.category}) — Author Reply:** ${developerAnswers[q.id].trim()}`
      );
    if (answeredEntries.length === 0) return baseComment;
    return `${baseComment}\n\n### Author Responses\n${answeredEntries.join('\n')}`;
  };

  return (
    <div className="bg-[#111113] border border-[#232329] rounded-xl flex flex-col overflow-hidden">
      {/* PR Thread Header */}
      <div className="px-5 py-3.5 border-b border-[#232329] bg-[#141417] flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded-full bg-white text-black flex items-center justify-center font-mono text-[11px] font-bold">
            NS
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="font-semibold text-zinc-100">nemosec-auditor</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-800 text-zinc-300 border border-zinc-700">
              bot
            </span>
            <span className="text-zinc-400">commented on</span>
            {prUrl ? (
              <a
                href={prUrl}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-zinc-200 hover:underline inline-flex items-center gap-1"
              >
                {prUrl.replace('https://github.com/', '')}
                <ExternalLink className="w-3 h-3 text-zinc-400" />
              </a>
            ) : (
              <span className="font-mono text-zinc-300">Pull Request</span>
            )}
          </div>
        </div>

        {socraticAnalysis && (
          <button
            onClick={() => onPostCommentToPR(buildCombinedCommentBody())}
            disabled={isPostingComment}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium bg-white text-black hover:bg-zinc-200 transition disabled:opacity-50"
          >
            <Send className="w-3 h-3" />
            {isPostingComment ? 'Syncing...' : 'Sync Replies to PR'}
          </button>
        )}
      </div>

      {/* Body */}
      <div className="p-5 space-y-5 flex-1">
        {!socraticAnalysis ? (
          <div className="py-16 text-center text-xs text-zinc-500 font-mono">
            Streaming PR review &amp; Socratic questions...
          </div>
        ) : (
          <>
            {/* 1. Check-In Commit Record (If Vulnerability Was Fixed in Same PR) OR Clean PR Notice */}
            {hadVulnerability ? (
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] p-3.5 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2 font-semibold text-emerald-300">
                    <GitCommit className="w-4 h-4 shrink-0" />
                    <span>Security Vulnerability Fixed as Part of This PR</span>
                  </div>
                  <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-black/50 text-emerald-300 border border-emerald-500/30">
                    {githubPushResult?.branch_name || 'feat/merchant-ledger-filter'}
                    {githubPushResult?.commit_sha ? ` @ ${githubPushResult.commit_sha}` : ''}
                  </span>
                </div>

                <div className="px-3 py-2 rounded bg-[#09090b] border border-[#232329] font-mono text-[11px] text-zinc-200 leading-relaxed">
                  <span className="text-zinc-500">Check-In Comment: </span>
                  {githubPushResult?.commit_message ||
                    'fix(secops): address security vulnerability in PR — Snyk issue resolved (0 issues)'}
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/[0.05] px-3.5 py-2.5 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 text-emerald-300 font-medium">
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                  <span>
                    No security vulnerabilities found (Snyk: 0 issues) — Commenting Socratic review only, code untouched.
                  </span>
                </div>
              </div>
            )}

            {/* 2. Executive PR Summary */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                Architectural Review Summary
              </div>
              <p className="text-sm text-zinc-200 leading-relaxed">{summary}</p>
            </div>

            {/* 3. Probing Socratic Questions inside the PR Comment */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                  <MessageSquare className="w-3.5 h-3.5 text-zinc-400" />
                  Socratic Questions for PR Author ({questions.length})
                </span>
                <span className="text-[11px] text-zinc-500">
                  Posted to PR Conversation
                </span>
              </div>

              <div className="divide-y divide-[#232329] border border-[#232329] rounded-lg bg-[#0c0c0e] overflow-hidden">
                {questions.map((q, idx) => (
                  <div key={q.id || idx} className="p-4 space-y-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono font-semibold text-zinc-400">
                          Q{idx + 1}
                        </span>
                        <span className="text-xs font-semibold text-zinc-200">
                          {q.category}
                        </span>
                      </div>
                      {q.target_line && (
                        <span className="text-[11px] font-mono text-zinc-400 px-1.5 py-0.5 rounded bg-[#16161a] border border-[#25252b]">
                          L{q.target_line}
                        </span>
                      )}
                    </div>

                    <p className="text-[13px] font-medium text-white leading-snug">
                      {q.question}
                    </p>

                    <p className="text-xs text-zinc-400 leading-relaxed">
                      {q.why_it_matters}
                    </p>

                    <div className="pt-1 flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                      <input
                        type="text"
                        value={developerAnswers[q.id] || ''}
                        onChange={(e) =>
                          setDeveloperAnswers((prev) => ({ ...prev, [q.id]: e.target.value }))
                        }
                        placeholder="Reply to this question in PR thread..."
                        className="flex-1 px-3 py-1.5 rounded-md bg-[#121215] border border-[#25252b] text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
                      />
                      <button
                        type="button"
                        onClick={() => toggleInsight(q.id || idx)}
                        className="px-2.5 py-1.5 rounded-md bg-[#16161a] hover:bg-[#1e1e24] border border-[#27272f] text-[11px] font-mono text-zinc-300 shrink-0 transition"
                      >
                        {expandedInsight[q.id || idx] ? 'Hide Answer Key' : 'Expected Insight'}
                      </button>
                    </div>

                    {expandedInsight[q.id || idx] && (
                      <div className="p-2.5 rounded bg-[#141418] border border-[#27272f] text-xs text-zinc-300">
                        <span className="font-mono text-[11px] text-emerald-400 uppercase mr-1.5">
                          Expected:
                        </span>
                        {q.expected_insight}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* 4. Architectural Trade-offs */}
            {tradeoffs.length > 0 && (
              <div className="space-y-2">
                <div className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                  Design Trade-Offs Noted in Review
                </div>
                <div className="space-y-1.5">
                  {tradeoffs.map((item, i) => (
                    <div
                      key={i}
                      className="text-xs text-zinc-300 px-3 py-2 rounded-md bg-[#0c0c0e] border border-[#1f1f24] flex items-start gap-2"
                    >
                      <span className="text-zinc-500 font-mono">0{i + 1}</span>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 5. Collapsible PR Intent & Changelog */}
            <div className="border border-[#232329] rounded-lg bg-[#0c0c0e] overflow-hidden">
              <div
                onClick={() => setShowChangelog(!showChangelog)}
                className="px-3.5 py-2.5 flex items-center justify-between cursor-pointer hover:bg-[#141418] transition text-xs"
              >
                <div className="flex items-center gap-2 font-mono text-zinc-300">
                  {showChangelog ? (
                    <ChevronDown className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronRight className="w-3.5 h-3.5" />
                  )}
                  <span>Auto-Drafted PR Intent &amp; Changelog Markdown</span>
                </div>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleCopyDoc();
                  }}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#18181c] border border-[#27272f] text-[11px] text-zinc-300 hover:text-white"
                >
                  {copiedDoc ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" /> Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" /> Copy
                    </>
                  )}
                </button>
              </div>
              {showChangelog && (
                <pre className="p-3.5 border-t border-[#232329] text-[11px] font-mono text-zinc-300 whitespace-pre-wrap leading-relaxed">
                  {prIntentMarkdown}
                </pre>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

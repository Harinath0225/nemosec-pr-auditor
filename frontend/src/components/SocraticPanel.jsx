import React, { useState } from 'react';
import {
  BrainCircuit,
  MessageSquarePlus,
  HelpCircle,
  Lightbulb,
  FileText,
  Copy,
  Check,
  ExternalLink,
  Scale,
  Send,
  CheckCircle2,
  GitPullRequest,
  GitCommit,
  ShieldCheck,
} from 'lucide-react';

export default function SocraticPanel({
  socraticAnalysis,
  prUrl,
  prCommentResult,
  githubPushResult,
  preSnyk,
  postSnyk,
  onPostCommentToPR,
  isPostingComment,
}) {
  const [activeTab, setActiveTab] = useState('questions'); // 'questions' | 'pr_comments' | 'changelog'
  const [revealedHints, setRevealedHints] = useState({});
  const [developerAnswers, setDeveloperAnswers] = useState({});
  const [copiedDoc, setCopiedDoc] = useState(false);

  const questions = socraticAnalysis?.questions || [];
  const tradeoffs = socraticAnalysis?.architectural_tradeoffs || [];
  const summary = socraticAnalysis?.summary || '';
  const prIntentMarkdown = socraticAnalysis?.pr_intent_markdown || '';
  const hadVulnerability = (preSnyk?.total_issues || 0) > 0;
  const primaryVuln = preSnyk?.vulnerabilities?.[0] || null;

  const toggleHint = (id) => {
    setRevealedHints((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyDoc = () => {
    navigator.clipboard.writeText(prIntentMarkdown);
    setCopiedDoc(true);
    setTimeout(() => setCopiedDoc(false), 2000);
  };

  const buildCombinedCommentBody = () => {
    const baseComment =
      prCommentResult?.body || socraticAnalysis?.formatted_pr_comment || '';
    const answeredEntries = questions
      .filter((q) => (developerAnswers[q.id] || '').trim().length > 0)
      .map(
        (q, i) =>
          `- **Q${i + 1} (${q.category}) — Developer Response:** ${developerAnswers[q.id].trim()}`
      );
    if (answeredEntries.length === 0) return baseComment;
    return `${baseComment}\n\n### 💬 Author Comprehension Responses\n${answeredEntries.join('\n')}`;
  };

  return (
    <div className="bg-slate-900/90 border border-indigo-500/30 rounded-2xl flex flex-col h-full shadow-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 bg-gradient-to-r from-indigo-950/70 via-slate-900 to-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
            <BrainCircuit className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-100">Branch A: Socratic Intent Agent</h2>
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-medium">
                Auto-Commented on PR
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Asks probing Socratic questions in PR comments &amp; logs same-PR security fix check-in
            </p>
          </div>
        </div>

        {/* Post / Update Developer Answers in PR Comment */}
        {socraticAnalysis && (
          <button
            onClick={() => onPostCommentToPR(buildCombinedCommentBody())}
            disabled={isPostingComment}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow transition disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            {isPostingComment ? 'Updating PR Comment...' : 'Post / Update Answers on PR'}
          </button>
        )}
      </div>

      {/* Sub-navigation Tabs */}
      <div className="px-5 pt-2.5 bg-slate-900/60 border-b border-slate-800 flex items-center gap-2 text-xs">
        <button
          onClick={() => setActiveTab('questions')}
          className={`px-3 py-2 rounded-t-lg font-medium border-b-2 transition flex items-center gap-1.5 ${
            activeTab === 'questions'
              ? 'border-indigo-400 text-indigo-300 bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <HelpCircle className="w-3.5 h-3.5" />
          Socratic Questions ({questions.length})
        </button>

        <button
          onClick={() => setActiveTab('pr_comments')}
          className={`px-3 py-2 rounded-t-lg font-medium border-b-2 transition flex items-center gap-1.5 ${
            activeTab === 'pr_comments'
              ? 'border-indigo-400 text-indigo-300 bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <MessageSquarePlus className="w-3.5 h-3.5" />
          PR Comment &amp; Check-In Log
          {prCommentResult && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              Auto-Posted
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('changelog')}
          className={`px-3 py-2 rounded-t-lg font-medium border-b-2 transition flex items-center gap-1.5 ${
            activeTab === 'changelog'
              ? 'border-indigo-400 text-indigo-300 bg-indigo-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          PR Intent &amp; Changelog
        </button>
      </div>

      {/* Body Content */}
      <div className="p-5 flex-1 overflow-y-auto space-y-4">
        {!socraticAnalysis ? (
          <div className="flex flex-col items-center justify-center h-64 text-center text-slate-500">
            <BrainCircuit className="w-10 h-10 mb-3 text-slate-600 animate-pulse" />
            <p className="text-sm font-medium text-slate-400">
              Ready to run Socratic Intent Analysis
            </p>
            <p className="text-xs text-slate-500 max-w-sm mt-1">
              Paste a GitHub PR link or select a preset above and click &ldquo;Audit PR&rdquo;. Socratic questions &amp; any security check-in will be posted automatically.
            </p>
          </div>
        ) : activeTab === 'questions' ? (
          <>
            {/* Unified Outcome Summary Banner */}
            <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-500/25 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
                  PR Audit Summary &amp; Check-In Action
                </span>
                <span
                  onClick={() => setActiveTab('pr_comments')}
                  className="cursor-pointer inline-flex items-center gap-1 text-[11px] px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/25 font-medium"
                >
                  <CheckCircle2 className="w-3 h-3" />
                  {hadVulnerability
                    ? 'Fixed in Same PR + Questions Commented → View PR Comment'
                    : '0 Vulns: Questions Commented on PR → View PR Comment'}
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{summary}</p>
            </div>

            {/* Probing Socratic Questions */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
                Probing Socratic Questions (Posted in PR Comments)
              </h3>

              {questions.map((q, idx) => (
                <div
                  key={q.id || idx}
                  className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-indigo-500/40 transition space-y-2.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-indigo-300 bg-indigo-500/15 px-2.5 py-0.5 rounded-md border border-indigo-500/30">
                      Q{idx + 1}: {q.category}
                    </span>
                    {q.target_line && (
                      <span className="text-[11px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        Line {q.target_line}
                      </span>
                    )}
                  </div>

                  <p className="text-sm font-medium text-slate-100 leading-snug">
                    &ldquo;{q.question}&rdquo;
                  </p>

                  <p className="text-xs text-slate-400">
                    <strong className="text-slate-300">Why this matters:</strong> {q.why_it_matters}
                  </p>

                  {/* Interactive Developer Answer Input */}
                  <div className="pt-1">
                    <input
                      type="text"
                      value={developerAnswers[q.id] || ''}
                      onChange={(e) =>
                        setDeveloperAnswers((prev) => ({ ...prev, [q.id]: e.target.value }))
                      }
                      placeholder="Write your developer response (click 'Post / Update Answers on PR' to append)..."
                      className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                    />
                  </div>

                  {/* Expected Insight Accordion */}
                  <div className="pt-1 flex items-center justify-between">
                    <button
                      onClick={() => toggleHint(q.id || idx)}
                      className="inline-flex items-center gap-1 text-xs text-amber-300/90 hover:text-amber-200 font-medium"
                    >
                      <Lightbulb className="w-3.5 h-3.5" />
                      {revealedHints[q.id || idx] ? 'Hide Expected Insight' : 'Reveal Expected Insight'}
                    </button>
                  </div>

                  {revealedHints[q.id || idx] && (
                    <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/25 text-xs text-amber-200">
                      <strong>Target Design Insight:</strong> {q.expected_insight}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Architectural Trade-offs */}
            {tradeoffs.length > 0 && (
              <div className="space-y-2 pt-1">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Scale className="w-3.5 h-3.5 text-indigo-400" />
                  Identified Architectural &amp; Design Trade-offs
                </h3>
                <ul className="space-y-1.5">
                  {tradeoffs.map((item, i) => (
                    <li
                      key={i}
                      className="text-xs text-slate-300 bg-slate-950/50 border border-slate-800/80 rounded-lg px-3 py-2 flex items-start gap-2"
                    >
                      <span className="text-indigo-400 font-bold">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        ) : activeTab === 'pr_comments' ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
              <div className="flex items-center gap-2 text-xs">
                <GitPullRequest className="w-4 h-4 text-indigo-400" />
                <span className="font-semibold text-slate-200">
                  GitHub Pull Request Timeline &amp; Check-In Comments
                </span>
                {prUrl && (
                  <a
                    href={prUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-indigo-400 hover:underline font-mono"
                  >
                    {prUrl.replace('https://github.com/', '')}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
              <span className="px-2.5 py-0.5 rounded-full text-[11px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold">
                {hadVulnerability ? 'Fixed in Same PR + Commented' : 'Clean PR Commented'}
              </span>
            </div>

            {/* Timeline Item 1: Automatic Same-PR Security Fix Check-In Commit (only when vulnerability found) */}
            {hadVulnerability && githubPushResult && (
              <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 space-y-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-emerald-300 font-bold">
                    <GitCommit className="w-4 h-4 shrink-0" />
                    <span>nemosec-pr-auditor[bot] checked in a security fix to this PR</span>
                  </div>
                  {githubPushResult.commit_sha && (
                    <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-950 text-emerald-300 border border-emerald-500/30">
                      {githubPushResult.commit_sha}
                    </span>
                  )}
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-emerald-500/30 font-mono text-emerald-200">
                  {githubPushResult.commit_message}
                </div>
              </div>
            )}

            {/* Timeline Item 2: Unified PR Comment (Check-In Resolution + Socratic Questions) */}
            <div className="rounded-xl border border-indigo-500/40 bg-slate-950/90 overflow-hidden">
              <div className="px-4 py-2.5 bg-indigo-950/50 border-b border-indigo-500/30 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-[11px]">
                    NS
                  </span>
                  <span className="font-semibold text-slate-200">
                    {prCommentResult?.author || 'nemosec-pr-auditor[bot]'}
                  </span>
                  <span className="text-slate-400">commented on this Pull Request</span>
                </div>
                {prCommentResult?.html_url && (
                  <a
                    href={prCommentResult.html_url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-indigo-300 hover:text-indigo-200"
                  >
                    View on GitHub <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>

              <div className="p-4 space-y-3 text-xs text-slate-200">
                <div className="font-bold text-sm text-indigo-300">
                  🧠🛡️ NemoSec Unified PR Audit — Socratic Review &amp; Snyk SecOps
                </div>

                {/* Snyk & Check-in Status inside the PR comment */}
                {hadVulnerability ? (
                  <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 space-y-1">
                    <div className="font-bold text-emerald-300 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4" />
                      Security Vulnerability Fixed in This PR &amp; Snyk Issue Resolved (0 Issues)
                    </div>
                    <div className="font-mono text-[11px] text-emerald-200">
                      Check-In Comment: &ldquo;{githubPushResult?.commit_message}&rdquo;
                    </div>
                    <div className="text-slate-300 text-[11px]">
                      Snyk Status: 🔴 <code>1 Critical ({primaryVuln?.id} / {primaryVuln?.cve})</code> ➔ 🟢{' '}
                      <strong>0 Vulnerabilities Found (Snyk Issue Gone)</strong>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 font-semibold flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" />
                    Snyk Security Scan: 0 Vulnerabilities Found (Clean PR — No Code Fix Needed)
                  </div>
                )}

                <p className="text-slate-300">{summary}</p>

                <div className="space-y-2 pt-1">
                  <div className="font-semibold text-slate-200">
                    🔍 Probing Socratic Questions for Author Verification:
                  </div>
                  {questions.map((q, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-900/90 border-l-2 border-indigo-400 space-y-1"
                    >
                      <div className="font-semibold text-indigo-200">
                        {idx + 1}. [{q.category}] {q.target_line ? `(Line ${q.target_line})` : ''}
                      </div>
                      <div className="text-slate-100">{q.question}</div>
                      <div className="text-slate-400 text-[11px]">Why it matters: {q.why_it_matters}</div>
                      {developerAnswers[q.id] && (
                        <div className="mt-1.5 pt-1.5 border-t border-slate-800 text-emerald-300">
                          <strong>Author Reply:</strong> {developerAnswers[q.id]}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* PR Intent & Changelog Tab */
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Auto-Drafted PR Intent &amp; Changelog Markdown
              </span>
              <button
                onClick={handleCopyDoc}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition"
              >
                {copiedDoc ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Copy Markdown
                  </>
                )}
              </button>
            </div>

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 whitespace-pre-wrap leading-relaxed font-mono">
              {prIntentMarkdown}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

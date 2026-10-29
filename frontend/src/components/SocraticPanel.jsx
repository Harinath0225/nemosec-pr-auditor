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
} from 'lucide-react';

export default function SocraticPanel({
  socraticAnalysis,
  prUrl,
  prCommentResult,
  secopsPrComment,
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

  const toggleHint = (id) => {
    setRevealedHints((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyDoc = () => {
    navigator.clipboard.writeText(prIntentMarkdown);
    setCopiedDoc(true);
    setTimeout(() => setCopiedDoc(false), 2000);
  };

  const buildCombinedCommentBody = () => {
    const baseComment = socraticAnalysis?.formatted_pr_comment || '';
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
                PR Comprehension & Docs
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Architectural trade-offs, probing Socratic PR review comments & structured changelog
            </p>
          </div>
        </div>

        {/* Post / Sync to GitHub PR Button */}
        {socraticAnalysis && (
          <button
            onClick={() => onPostCommentToPR(buildCombinedCommentBody())}
            disabled={isPostingComment}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow transition disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            {isPostingComment
              ? 'Posting to PR...'
              : prCommentResult?.posted_live
              ? 'Update PR Comment'
              : 'Post Socratic Review to PR'}
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
          GitHub PR Comments
          {(prCommentResult || secopsPrComment) && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              {(prCommentResult ? 1 : 0) + (secopsPrComment ? 1 : 0)}
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
          PR Intent & Changelog
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
              Paste a GitHub PR link or select a preset above and click &ldquo;Run Dual-Branch PR Audit&rdquo; to generate Socratic questions and post them to your PR.
            </p>
          </div>
        ) : activeTab === 'questions' ? (
          <>
            {/* Executive Summary Banner */}
            <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-500/25">
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
                  Architectural & Intent Analysis
                </span>
                {prCommentResult && (
                  <span
                    onClick={() => setActiveTab('pr_comments')}
                    className="cursor-pointer inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/25"
                  >
                    <CheckCircle2 className="w-3 h-3" />
                    {prCommentResult.posted_live ? 'Posted to GitHub PR' : 'Synced to PR Comment Thread'}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{summary}</p>
            </div>

            {/* Probing Socratic Questions */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
                Probing Socratic Questions (Shown in PR Review Comments)
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
                      placeholder="Write your developer response (will be included in PR comment)..."
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
                  Identified Architectural & Design Trade-offs
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
            <div className="flex items-center justify-between gap-2 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
              <div className="flex items-center gap-2 text-xs">
                <GitPullRequest className="w-4 h-4 text-indigo-400" />
                <span className="font-semibold text-slate-200">
                  GitHub Pull Request Conversation Thread
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
              {prCommentResult?.posted_live ? (
                <span className="px-2.5 py-0.5 rounded-full text-[11px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold">
                  Live on GitHub PR
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded-full text-[11px] bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-medium">
                  PR Comment Synced
                </span>
              )}
            </div>

            {/* Comment #1: Socratic Code Review Comment */}
            <div className="rounded-xl border border-indigo-500/40 bg-slate-950/90 overflow-hidden">
              <div className="px-4 py-2.5 bg-indigo-950/50 border-b border-indigo-500/30 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold text-[11px]">
                    NS
                  </span>
                  <span className="font-semibold text-slate-200">
                    {prCommentResult?.author || 'nemosec-socratic-bot'}
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
                  🧠 NemoSec Socratic Code Review & PR Intent Audit
                </div>
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

            {/* Comment #2: SecOps Remediation & Snyk 0-Vulnerability Resolution Comment (when applied) */}
            {secopsPrComment && (
              <div className="rounded-xl border border-emerald-500/40 bg-slate-950/90 overflow-hidden">
                <div className="px-4 py-2.5 bg-emerald-950/50 border-b border-emerald-500/30 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-6 h-6 rounded-full bg-emerald-600 text-white flex items-center justify-center font-bold text-[11px]">
                      SO
                    </span>
                    <span className="font-semibold text-emerald-200">
                      {secopsPrComment.author || 'nemosec-secops-bot'}
                    </span>
                    <span className="text-slate-400">posted Snyk Remediation Verification</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold text-[10px]">
                    SNYK ISSUE RESOLVED (0 VULNS)
                  </span>
                </div>
                <pre className="p-4 text-[11px] text-slate-300 whitespace-pre-wrap font-mono overflow-x-auto">
                  {secopsPrComment.body}
                </pre>
              </div>
            )}
          </div>
        ) : (
          /* PR Intent & Changelog Tab */
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Auto-Drafted PR Intent & Changelog Markdown
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

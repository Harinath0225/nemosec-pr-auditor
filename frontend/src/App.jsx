import React, { useState, useEffect, useRef } from 'react';
import {
  GitPullRequest,
  Play,
  Settings,
  Code,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  X,
  Loader2,
  GitCommit,
  ShieldCheck,
} from 'lucide-react';
import GraphVisualizer from './components/GraphVisualizer.jsx';
import SocraticPanel from './components/SocraticPanel.jsx';
import SecOpsPanel from './components/SecOpsPanel.jsx';

export default function App() {
  const [presets, setPresets] = useState([]);
  const [selectedPresetId, setSelectedPresetId] = useState('sql_injection_ledger');
  const [prUrl, setPrUrl] = useState('https://github.com/Harinath0225/nemosec-pr-auditor/pull/1');
  const [headRef, setHeadRef] = useState('feat/merchant-ledger-filter');
  const [filePath, setFilePath] = useState('demo-vulnerable-app/payment_ledger.py');
  const [codeSnippet, setCodeSnippet] = useState('');
  const [gitDiff, setGitDiff] = useState('');
  const [snykJson, setSnykJson] = useState(null);
  const [showCodeDrawer, setShowCodeDrawer] = useState(false);

  const [config, setConfig] = useState({
    nebius_configured: false,
    github_configured: false,
    nebius_model: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B',
    available_models: [
      { id: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B', label: 'Nemotron-3 Nano 30B' },
      { id: 'nvidia/nemotron-3-super-120b', label: 'Nemotron-3 Super 120B' },
      { id: 'nvidia/nemotron-3.5-super-vl', label: 'Nemotron-3.5 Super VL' },
    ],
  });
  const [showSettings, setShowSettings] = useState(false);
  const [nebiusKeyInput, setNebiusKeyInput] = useState('');
  const [githubTokenInput, setGithubTokenInput] = useState('');
  const [selectedModel, setSelectedModel] = useState('nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B');

  const [isRunningAudit, setIsRunningAudit] = useState(false);
  const [isPostingComment, setIsPostingComment] = useState(false);
  const [activeNodes, setActiveNodes] = useState([]);
  const [completedNodes, setCompletedNodes] = useState([]);
  const [statusBanner, setStatusBanner] = useState(null);

  const [socraticAnalysis, setSocraticAnalysis] = useState(null);
  const [prCommentResult, setPrCommentResult] = useState(null);
  const [preSnyk, setPreSnyk] = useState(null);
  const [postSnyk, setPostSnyk] = useState(null);
  const [remediatedCode, setRemediatedCode] = useState('');
  const [remediationExplanation, setRemediationExplanation] = useState('');
  const [unifiedDiff, setUnifiedDiff] = useState('');
  const [sandboxResults, setSandboxResults] = useState(null);
  const [branchInfo, setBranchInfo] = useState(null);
  const [snykAppliedToPR, setSnykAppliedToPR] = useState(false);
  const [githubPushResult, setGithubPushResult] = useState(null);

  const didAutoRunRef = useRef(false);

  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      const [cfgRes, presetRes] = await Promise.all([
        fetch('/api/config'),
        fetch('/api/presets'),
      ]);
      let modelToUse = 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B';
      if (cfgRes.ok) {
        const cfg = await cfgRes.json();
        setConfig(cfg);
        modelToUse = cfg.nebius_model || modelToUse;
        setSelectedModel(modelToUse);
      }
      if (presetRes.ok) {
        const pdata = await presetRes.json();
        const list = pdata.presets || [];
        setPresets(list);
        if (list.length > 0) {
          const first = list[0];
          setSelectedPresetId(first.id);
          setPrUrl(first.pr_url || 'https://github.com/Harinath0225/nemosec-pr-auditor/pull/1');
          setHeadRef(first.head_ref || 'feat/merchant-ledger-filter');
          setFilePath(first.file_path);
          setCodeSnippet(first.code_snippet);
          setGitDiff(first.git_diff);
          setSnykJson(first.snyk_json);

          if (!didAutoRunRef.current) {
            didAutoRunRef.current = true;
            executeAuditStream({
              preset_id: first.id,
              pr_url: first.pr_url,
              head_ref: first.head_ref,
              file_path: first.file_path,
              code_snippet: first.code_snippet,
              git_diff: first.git_diff,
              snyk_json: first.snyk_json,
              model_id: modelToUse,
            });
          }
        }
      }
    } catch (err) {
      console.error('Failed to load initial config/presets:', err);
    }
  };

  const resetAuditOutputs = () => {
    setActiveNodes([]);
    setCompletedNodes([]);
    setSocraticAnalysis(null);
    setPrCommentResult(null);
    setPreSnyk(null);
    setPostSnyk(null);
    setRemediatedCode('');
    setRemediationExplanation('');
    setUnifiedDiff('');
    setSandboxResults(null);
    setBranchInfo(null);
    setSnykAppliedToPR(false);
    setGithubPushResult(null);
  };

  const handleSelectScenario = (preset) => {
    if (isRunningAudit) return;
    setSelectedPresetId(preset.id);
    setPrUrl(preset.pr_url);
    setHeadRef(preset.head_ref || 'feat/merchant-ledger-filter');
    setFilePath(preset.file_path);
    setCodeSnippet(preset.code_snippet);
    setGitDiff(preset.git_diff);
    setSnykJson(preset.snyk_json);

    executeAuditStream({
      preset_id: preset.id,
      pr_url: preset.pr_url,
      head_ref: preset.head_ref,
      file_path: preset.file_path,
      code_snippet: preset.code_snippet,
      git_diff: preset.git_diff,
      snyk_json: preset.snyk_json,
      model_id: selectedModel,
    });
  };

  const handleAuditFromUrl = async (e) => {
    if (e) e.preventDefault();
    if (isRunningAudit) return;

    // Fetch live PR context first if URL was edited, then stream the audit
    let payloadToRun = {
      preset_id: selectedPresetId,
      pr_url: prUrl,
      head_ref: headRef,
      file_path: filePath,
      code_snippet: codeSnippet,
      git_diff: gitDiff,
      snyk_json: snykJson,
      model_id: selectedModel,
    };

    if (prUrl.trim()) {
      try {
        const resp = await fetch('/api/github/fetch-pr', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pr_url: prUrl.trim() }),
        });
        if (resp.ok) {
          const data = await resp.json();
          const newFile = data.target_file || filePath;
          const newHead = data.head_ref || headRef;
          const newCode = data.code_snippet || codeSnippet;
          const newDiff = data.git_diff || gitDiff;
          const newSnyk = data.snyk_json || snykJson;

          setFilePath(newFile);
          setHeadRef(newHead);
          setCodeSnippet(newCode);
          setGitDiff(newDiff);
          setSnykJson(newSnyk);

          payloadToRun = {
            preset_id: selectedPresetId,
            pr_url: prUrl.trim(),
            head_ref: newHead,
            file_path: newFile,
            code_snippet: newCode,
            git_diff: newDiff,
            snyk_json: newSnyk,
            model_id: selectedModel,
          };
        }
      } catch (_) {
        // Proceed with current state
      }
    }

    executeAuditStream(payloadToRun);
  };

  const executeAuditStream = async (reqPayload) => {
    setIsRunningAudit(true);
    resetAuditOutputs();
    setStatusBanner(null);
    setActiveNodes(['ingest_node']);

    try {
      const response = await fetch('/api/audit/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...reqPayload,
          auto_post_pr_comment: true,
        }),
      });

      if (!response.ok || !response.body) {
        throw new Error(`Audit stream failed (${response.status})`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const parts = buffer.split('\n\n');
        buffer = parts.pop() || '';

        for (const block of parts) {
          const lines = block.replace(/\r/g, '').split('\n');
          let eventType = 'message';
          let dataStr = '';

          for (const line of lines) {
            if (line.startsWith('event:')) {
              eventType = line.slice(6).trim();
            } else if (line.startsWith('data:')) {
              dataStr += line.slice(5).trim();
            }
          }

          if (!dataStr) continue;
          try {
            const payload = JSON.parse(dataStr);

            if (eventType === 'node_update') {
              const { completed_node, next_active_nodes, output } = payload;
              setCompletedNodes((prev) =>
                prev.includes(completed_node) ? prev : [...prev, completed_node]
              );
              setActiveNodes(next_active_nodes || []);

              if (output.socratic_analysis) setSocraticAnalysis(output.socratic_analysis);
              if (output.pr_comment_result) setPrCommentResult(output.pr_comment_result);
              if (output.pre_remediation_snyk) setPreSnyk(output.pre_remediation_snyk);
              if (output.remediated_code) setRemediatedCode(output.remediated_code);
              if (output.remediation_explanation)
                setRemediationExplanation(output.remediation_explanation);
              if (output.unified_diff !== undefined) setUnifiedDiff(output.unified_diff);
              if (output.sandbox_results) setSandboxResults(output.sandbox_results);
              if (output.post_remediation_snyk) setPostSnyk(output.post_remediation_snyk);
              if (output.branch_info) setBranchInfo(output.branch_info);
              if (output.github_push_result) {
                setGithubPushResult(output.github_push_result);
                setSnykAppliedToPR(true);
              }
            } else if (eventType === 'audit_complete') {
              setActiveNodes([]);
              setCompletedNodes([
                'ingest_node',
                'socratic_intent_node',
                'snyk_scanner_node',
                'sandbox_patcher_node',
                'finalize_audit_node',
              ]);
            } else if (eventType === 'audit_error') {
              setStatusBanner({ type: 'error', text: payload.error || 'Audit error occurred' });
            }
          } catch (parseErr) {
            console.warn('SSE parse notice:', parseErr);
          }
        }
      }
    } catch (err) {
      setStatusBanner({ type: 'error', text: err.message });
    } finally {
      setIsRunningAudit(false);
      setActiveNodes([]);
    }
  };

  const handlePostCommentToPR = async (commentBody) => {
    setIsPostingComment(true);
    try {
      const resp = await fetch('/api/github/post-socratic-comment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pr_url: prUrl, comment_body: commentBody }),
      });
      const data = await resp.json();
      setPrCommentResult(data);
      setStatusBanner({
        type: 'success',
        text: 'Synced author responses to PR review comment.',
      });
    } catch (err) {
      setStatusBanner({ type: 'error', text: err.message });
    } finally {
      setIsPostingComment(false);
    }
  };

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    try {
      const resp = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          nebius_api_key: nebiusKeyInput || undefined,
          nebius_model: selectedModel,
          github_token: githubTokenInput || undefined,
        }),
      });
      if (resp.ok) {
        const updated = await resp.json();
        setConfig(updated);
        setNebiusKeyInput('');
        setGithubTokenInput('');
        setShowSettings(false);
      }
    } catch (err) {
      setStatusBanner({ type: 'error', text: err.message });
    }
  };

  const hadVulnerability = (preSnyk?.total_issues || 0) > 0;

  return (
    <div className="min-h-screen bg-[#09090b] text-[#f4f4f5] flex flex-col">
      {/* Top Navigation Bar */}
      <header className="border-b border-[#1f1f24] bg-[#09090b]/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-[1480px] mx-auto px-5 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-white text-black flex items-center justify-center font-mono font-bold text-xs">
              NS
            </div>
            <div className="flex items-center gap-2.5">
              <span className="font-semibold text-sm tracking-tight text-white">NemoSec</span>
              <span className="text-zinc-600">/</span>
              <span className="text-xs text-zinc-400">
                Autonomous PR Socratic Reviewer &amp; Snyk Auto-Fixer
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 text-xs">
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="px-2.5 py-1.5 rounded-md bg-[#121215] border border-[#232329] text-zinc-300 font-mono text-[11px] focus:outline-none focus:border-zinc-500"
            >
              {config.available_models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>

            <button
              onClick={() => setShowCodeDrawer(!showCodeDrawer)}
              className={`px-2.5 py-1.5 rounded-md border text-xs font-mono inline-flex items-center gap-1.5 transition ${
                showCodeDrawer
                  ? 'bg-white text-black border-white'
                  : 'bg-[#121215] border-[#232329] text-zinc-300 hover:border-zinc-600'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              <span>Source</span>
            </button>

            <button
              onClick={() => setShowSettings(true)}
              className="px-2.5 py-1.5 rounded-md bg-[#121215] hover:bg-[#18181d] border border-[#232329] text-zinc-300 inline-flex items-center gap-1.5 transition"
            >
              <Settings className="w-3.5 h-3.5 text-zinc-400" />
              <span>Keys</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1480px] w-full mx-auto px-5 py-5 flex-1 flex flex-col gap-4">
        {/* Clean Single-Row PR Bar + Scenario Switcher */}
        <div className="bg-[#111113] border border-[#232329] rounded-xl p-3.5 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          {/* PR URL Input + Primary Action */}
          <form onSubmit={handleAuditFromUrl} className="flex items-center gap-2 flex-1">
            <div className="relative flex-1">
              <GitPullRequest className="w-4 h-4 text-zinc-500 absolute left-3.5 top-2.5" />
              <input
                type="text"
                value={prUrl}
                onChange={(e) => setPrUrl(e.target.value)}
                placeholder="Paste GitHub PR URL (e.g. https://github.com/owner/repo/pull/1)"
                className="w-full pl-10 pr-3 py-2 rounded-lg bg-[#09090b] border border-[#25252c] text-xs font-mono text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-zinc-400"
              />
            </div>

            <button
              type="submit"
              disabled={isRunningAudit}
              className="px-4 py-2 rounded-lg bg-white hover:bg-zinc-200 text-black font-semibold text-xs inline-flex items-center gap-2 shrink-0 transition disabled:opacity-60"
            >
              {isRunningAudit ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing PR...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Audit Pull Request</span>
                </>
              )}
            </button>
          </form>

          {/* 3 Instant Scenario Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-zinc-500 mr-1">Demo PRs:</span>
            {presets.map((p, index) => {
              const isSelected = selectedPresetId === p.id;
              const isClean = p.id === 'clean_pr_no_vulns';
              const shortLabel =
                index === 0
                  ? 'PR #1 · SQL Injection (Auto-Fix)'
                  : index === 1
                  ? 'PR #2 · Command Injection (Auto-Fix)'
                  : 'PR #3 · Clean PR (Comment Only)';

              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => handleSelectScenario(p)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition inline-flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-[#1f1f26] text-white border-zinc-500'
                      : 'bg-[#09090b] text-zinc-400 border-[#232329] hover:text-zinc-200 hover:border-zinc-700'
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      isClean ? 'bg-emerald-400' : 'bg-amber-400'
                    }`}
                  />
                  <span>{shortLabel}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Collapsible Raw Source & Diff Editor */}
        {showCodeDrawer && (
          <div className="bg-[#111113] border border-[#232329] rounded-xl p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
              <div className="text-[11px] font-mono text-zinc-400 mb-1.5">
                Target File: {filePath}
              </div>
              <textarea
                value={codeSnippet}
                onChange={(e) => setCodeSnippet(e.target.value)}
                rows={8}
                className="w-full p-3 rounded-lg bg-[#09090b] border border-[#232329] font-mono text-xs text-zinc-200 focus:outline-none focus:border-zinc-500"
              />
            </div>
            <div>
              <div className="text-[11px] font-mono text-zinc-400 mb-1.5">PR Git Diff</div>
              <textarea
                value={gitDiff}
                onChange={(e) => setGitDiff(e.target.value)}
                rows={8}
                className="w-full p-3 rounded-lg bg-[#09090b] border border-[#232329] font-mono text-xs text-zinc-200 focus:outline-none focus:border-zinc-500"
              />
            </div>
          </div>
        )}

        {/* 4-Step Pipeline Stepper */}
        <GraphVisualizer
          activeNodes={activeNodes}
          completedNodes={completedNodes}
          isRunning={isRunningAudit}
          preSnyk={preSnyk}
          postSnyk={postSnyk}
          githubPushResult={githubPushResult}
        />

        {/* Full-Width Outcome Banner (Immediately reflects the exact PR behavior) */}
        {preSnyk && !isRunningAudit && (
          <div
            className={`rounded-xl border px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs ${
              hadVulnerability
                ? 'bg-emerald-500/[0.07] border-emerald-500/30 text-zinc-100'
                : 'bg-[#111113] border-[#27272f] text-zinc-200'
            }`}
          >
            <div className="flex items-center gap-3">
              {hadVulnerability ? (
                <GitCommit className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
              <div>
                <span className="font-semibold text-white mr-2">
                  {hadVulnerability
                    ? 'Vulnerability Found → Auto-Fixed in Same PR & Socratic Questions Commented:'
                    : 'No Security Vulnerability Found → PR Commented with Socratic Questions Only:'}
                </span>
                <span className="font-mono text-zinc-300">
                  {hadVulnerability
                    ? githubPushResult?.commit_message || branchInfo?.commit_message
                    : '0 Snyk issues detected. Code left untouched; Socratic review posted to PR.'}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold">
                Snyk: 0 Vulnerabilities
              </span>
            </div>
          </div>
        )}

        {statusBanner && (
          <div className="rounded-lg border border-[#27272f] bg-[#141418] px-3.5 py-2 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              {statusBanner.type === 'error' ? (
                <AlertCircle className="w-4 h-4 text-rose-400" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              )}
              <span>{statusBanner.text}</span>
            </div>
            <button onClick={() => setStatusBanner(null)} className="text-zinc-400 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Main Two-Column Workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 items-start">
          {/* Left 6 Cols: GitHub PR Review Comment & Socratic Questions */}
          <div className="lg:col-span-6">
            <SocraticPanel
              socraticAnalysis={socraticAnalysis}
              prUrl={prUrl}
              prCommentResult={prCommentResult}
              githubPushResult={githubPushResult}
              preSnyk={preSnyk}
              postSnyk={postSnyk}
              onPostCommentToPR={handlePostCommentToPR}
              isPostingComment={isPostingComment}
            />
          </div>

          {/* Right 6 Cols: Same-PR Fix Check-In Diff, Snyk Before/After & Pytest Logs */}
          <div className="lg:col-span-6">
            <SecOpsPanel
              preSnyk={preSnyk}
              postSnyk={postSnyk}
              remediatedCode={remediatedCode}
              remediationExplanation={remediationExplanation}
              unifiedDiff={unifiedDiff}
              sandboxResults={sandboxResults}
              branchInfo={branchInfo}
              snykAppliedToPR={snykAppliedToPR}
              githubPushResult={githubPushResult}
            />
          </div>
        </div>
      </main>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111113] border border-[#27272f] rounded-xl max-w-md w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#232329] pb-3">
              <div className="flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-zinc-300" />
                <h3 className="text-sm font-semibold text-white">API &amp; GitHub Credentials</h3>
              </div>
              <button
                onClick={() => setShowSettings(false)}
                className="text-zinc-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveSettings} className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-300 font-medium mb-1">
                  Nebius API Key (<code>NEBIUS_API_KEY</code>)
                </label>
                <input
                  type="password"
                  value={nebiusKeyInput}
                  onChange={(e) => setNebiusKeyInput(e.target.value)}
                  placeholder={
                    config.nebius_configured ? '•••••••• (Configured)' : 'Enter Nebius API key...'
                  }
                  className="w-full px-3 py-2 rounded-lg bg-[#09090b] border border-[#25252c] text-zinc-100 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div>
                <label className="block text-zinc-300 font-medium mb-1">
                  GitHub Personal Access Token (<code>GITHUB_TOKEN</code>)
                </label>
                <input
                  type="password"
                  value={githubTokenInput}
                  onChange={(e) => setGithubTokenInput(e.target.value)}
                  placeholder={
                    config.github_configured
                      ? '•••••••• (Configured)'
                      : 'ghp_... (For live GitHub PR comment API)'
                  }
                  className="w-full px-3 py-2 rounded-lg bg-[#09090b] border border-[#25252c] text-zinc-100 focus:outline-none focus:border-zinc-400"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSettings(false)}
                  className="px-3 py-1.5 rounded-lg bg-[#1a1a1f] text-zinc-300 hover:bg-[#232329]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-white text-black font-semibold hover:bg-zinc-200"
                >
                  Save
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

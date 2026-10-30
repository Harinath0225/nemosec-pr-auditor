import React, { useState, useEffect } from 'react';
import {
  Shield,
  GitPullRequest,
  Play,
  Settings,
  Code,
  CheckCircle2,
  AlertCircle,
  DownloadCloud,
  KeyRound,
  X,
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

  // Config & Settings modal state
  const [config, setConfig] = useState({
    nebius_configured: false,
    github_configured: false,
    nebius_model: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B',
    available_models: [
      { id: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B', label: 'NVIDIA Nemotron-3 Nano 30B-A3B (Fast)' },
      { id: 'nvidia/nemotron-3-super-120b', label: 'NVIDIA Nemotron-3 Super 120B (Reasoning)' },
      { id: 'nvidia/nemotron-3.5-super-vl', label: 'NVIDIA Nemotron-3.5 Super VL' },
    ],
  });
  const [showSettings, setShowSettings] = useState(false);
  const [nebiusKeyInput, setNebiusKeyInput] = useState('');
  const [githubTokenInput, setGithubTokenInput] = useState('');
  const [selectedModel, setSelectedModel] = useState('nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B');

  // LangGraph & Audit execution state
  const [isRunningAudit, setIsRunningAudit] = useState(false);
  const [isFetchingPR, setIsFetchingPR] = useState(false);
  const [isPostingComment, setIsPostingComment] = useState(false);
  const [activeNodes, setActiveNodes] = useState([]);
  const [completedNodes, setCompletedNodes] = useState([]);
  const [statusBanner, setStatusBanner] = useState(null);

  // Branch A & Branch B outputs
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

  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      const [cfgRes, presetRes] = await Promise.all([
        fetch('/api/config'),
        fetch('/api/presets'),
      ]);
      if (cfgRes.ok) {
        const cfg = await cfgRes.json();
        setConfig(cfg);
        setSelectedModel(cfg.nebius_model || 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B');
      }
      if (presetRes.ok) {
        const pdata = await presetRes.json();
        const list = pdata.presets || [];
        setPresets(list);
        if (list.length > 0) {
          applyPreset(list[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load initial config/presets:', err);
    }
  };

  const applyPreset = (preset) => {
    setSelectedPresetId(preset.id);
    setPrUrl(preset.pr_url || 'https://github.com/Harinath0225/nemosec-pr-auditor/pull/1');
    setHeadRef(preset.head_ref || 'feat/merchant-ledger-filter');
    setFilePath(preset.file_path);
    setCodeSnippet(preset.code_snippet);
    setGitDiff(preset.git_diff);
    setSnykJson(preset.snyk_json);
    resetAuditOutputs();
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

  const handlePresetChange = (presetId) => {
    const found = presets.find((p) => p.id === presetId);
    if (found) applyPreset(found);
  };

  const handleFetchPR = async () => {
    if (!prUrl.trim()) return;
    setIsFetchingPR(true);
    setStatusBanner(null);
    try {
      const resp = await fetch('/api/github/fetch-pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pr_url: prUrl.trim() }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || 'Failed to fetch PR');
      }
      setFilePath(data.target_file || 'demo-vulnerable-app/payment_ledger.py');
      if (data.head_ref) setHeadRef(data.head_ref);
      if (data.code_snippet) setCodeSnippet(data.code_snippet);
      if (data.git_diff) setGitDiff(data.git_diff);
      if (data.snyk_json) setSnykJson(data.snyk_json);
      resetAuditOutputs();
      setStatusBanner({
        type: 'success',
        text: data.fetched_live
          ? `Fetched live GitHub PR #${data.pull_number} (${data.title}) — Branch: ${data.head_ref}`
          : `Loaded PR #${data.pull_number} (${data.target_file} on branch ${data.head_ref}) ready for audit.`,
      });
    } catch (err) {
      setStatusBanner({ type: 'error', text: err.message });
    } finally {
      setIsFetchingPR(false);
    }
  };

  const handleRunAudit = async () => {
    setIsRunningAudit(true);
    resetAuditOutputs();
    setStatusBanner(null);
    setActiveNodes(['ingest_node']);

    try {
      const response = await fetch('/api/audit/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          preset_id: selectedPresetId,
          pr_url: prUrl,
          head_ref: headRef,
          file_path: filePath,
          code_snippet: codeSnippet,
          git_diff: gitDiff,
          snyk_json: snykJson,
          model_id: selectedModel,
          auto_post_pr_comment: true,
        }),
      });

      if (!response.ok || !response.body) {
        throw new Error(`Audit stream failed with status ${response.status}`);
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

              const pushRes = payload.github_push_result;
              if (pushRes) {
                setStatusBanner({
                  type: 'success',
                  text: pushRes.message,
                });
              }
            } else if (eventType === 'audit_error') {
              setStatusBanner({ type: 'error', text: payload.error || 'Audit error occurred' });
            }
          } catch (parseErr) {
            console.warn('SSE chunk parse notice:', parseErr);
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
        text: data.posted_live
          ? 'Updated Socratic review & developer responses on GitHub PR!'
          : 'Updated Socratic review & developer responses in PR Comment Thread!',
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
        setStatusBanner({
          type: 'success',
          text: 'Configuration saved to .env and applied to runtime!',
        });
      }
    } catch (err) {
      setStatusBanner({ type: 'error', text: err.message });
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Header Bar */}
      <header className="border-b border-slate-800/90 bg-slate-900/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-500/20 to-emerald-500/20 border border-emerald-500/30 text-emerald-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-extrabold tracking-tight bg-gradient-to-r from-white via-indigo-200 to-emerald-300 bg-clip-text text-transparent">
                  NemoSec &amp; Socratic PR Auditor
                </h1>
                <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  Nebius Nemotron + LangGraph
                </span>
              </div>
              <p className="text-xs text-slate-400">
                1-Click Autonomous PR Auditor: Comments Socratic Questions &amp; Auto-Checks In Security Fixes on the Same PR
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 text-xs">
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
            >
              {config.available_models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>

            <button
              onClick={() => setShowSettings(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-800 border border-slate-700 text-slate-200 transition"
            >
              <Settings className="w-3.5 h-3.5 text-indigo-400" />
              <span>API &amp; GitHub Keys</span>
              <span
                className={`w-2 h-2 rounded-full ${
                  config.nebius_configured && config.github_configured
                    ? 'bg-emerald-400'
                    : 'bg-amber-400'
                }`}
              />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-4 flex-1 flex flex-col gap-4">
        {/* PR Link & Demo Control Bar */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 shadow-lg space-y-3">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center">
            {/* Preset Selector (4 cols) */}
            <div className="lg:col-span-4 flex flex-col gap-1">
              <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Select Demo PR Scenario (Vulnerable vs Clean)
              </label>
              <select
                value={selectedPresetId}
                onChange={(e) => handlePresetChange(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
              >
                {presets.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>

            {/* GitHub PR Link Input (5 cols) */}
            <div className="lg:col-span-5 flex flex-col gap-1">
              <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                <span>GitHub Pull Request URL</span>
                <span className="font-mono text-indigo-400 text-[10px]">
                  Same-PR Check-In &amp; Commenting
                </span>
              </label>
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <GitPullRequest className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={prUrl}
                    onChange={(e) => setPrUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo/pull/1"
                    className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <button
                  onClick={handleFetchPR}
                  disabled={isFetchingPR}
                  className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 inline-flex items-center gap-1.5 shrink-0 transition disabled:opacity-50"
                >
                  <DownloadCloud className="w-3.5 h-3.5 text-indigo-400" />
                  {isFetchingPR ? 'Fetching...' : 'Load PR'}
                </button>
              </div>
            </div>

            {/* Run Audit Primary Action (3 cols) */}
            <div className="lg:col-span-3 flex flex-col gap-1">
              <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                1-Click Audit &amp; Auto-Fix PR
              </label>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleRunAudit}
                  disabled={isRunningAudit}
                  className="flex-1 py-2 px-4 rounded-xl bg-gradient-to-r from-indigo-600 to-emerald-600 hover:from-indigo-500 hover:to-emerald-500 text-white font-bold text-xs shadow-lg shadow-indigo-500/20 inline-flex items-center justify-center gap-2 transition disabled:opacity-50"
                >
                  <Play className="w-4 h-4 fill-current" />
                  {isRunningAudit ? 'Auditing & Updating PR...' : 'Audit PR (Auto-Fix & Comment)'}
                </button>

                <button
                  onClick={() => setShowCodeDrawer(!showCodeDrawer)}
                  title="Inspect / Edit Source Code & Diff"
                  className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition"
                >
                  <Code className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Status Notification Banner */}
          {statusBanner && (
            <div
              className={`px-3.5 py-2 rounded-xl border text-xs flex items-center justify-between gap-2 ${
                statusBanner.type === 'error'
                  ? 'bg-rose-950/50 border-rose-500/40 text-rose-200'
                  : 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
              }`}
            >
              <div className="flex items-center gap-2">
                {statusBanner.type === 'error' ? (
                  <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                )}
                <span>{statusBanner.text}</span>
              </div>
              <button
                onClick={() => setStatusBanner(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Collapsible Source Code & Git Diff Inspector */}
          {showCodeDrawer && (
            <div className="pt-2 border-t border-slate-800 grid grid-cols-1 lg:grid-cols-2 gap-3">
              <div>
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span className="font-mono">Target File: {filePath}</span>
                  <span className="text-[11px]">Editable Python Source</span>
                </div>
                <textarea
                  value={codeSnippet}
                  onChange={(e) => setCodeSnippet(e.target.value)}
                  rows={10}
                  className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span className="font-mono">Git Diff Payload</span>
                  <span className="text-[11px]">PR Patch Context</span>
                </div>
                <textarea
                  value={gitDiff}
                  onChange={(e) => setGitDiff(e.target.value)}
                  rows={10}
                  className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>
          )}
        </div>

        {/* Live LangGraph DAG Visualizer */}
        <GraphVisualizer
          activeNodes={activeNodes}
          completedNodes={completedNodes}
          isRunning={isRunningAudit}
          snykResolved={Boolean(postSnyk && postSnyk.ok)}
        />

        {/* Dual-Branch Split-Screen Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 flex-1 min-h-[540px]">
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
      </main>

      {/* API & GitHub Token Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-indigo-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  Nebius Token Factory &amp; GitHub PR Credentials
                </h3>
              </div>
              <button
                onClick={() => setShowSettings(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveSettings} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Nebius Token Factory API Key (<code>NEBIUS_API_KEY</code>)
                </label>
                <input
                  type="password"
                  value={nebiusKeyInput}
                  onChange={(e) => setNebiusKeyInput(e.target.value)}
                  placeholder={
                    config.nebius_configured
                      ? '•••••••••••••••• (Configured — enter new to replace)'
                      : 'Enter Nebius API key...'
                  }
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  GitHub Personal Access Token (<code>GITHUB_TOKEN</code>)
                </label>
                <input
                  type="password"
                  value={githubTokenInput}
                  onChange={(e) => setGithubTokenInput(e.target.value)}
                  placeholder={
                    config.github_configured
                      ? '•••••••••••••••• (Configured — enter new to replace)'
                      : 'ghp_... (Optional: local git already pushes to your repo)'
                  }
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSettings(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold"
                >
                  Save to .env
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

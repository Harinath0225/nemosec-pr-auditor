"""
FastAPI backend for NemoSec & Socratic PR Auditor.
Provides SSE real-time LangGraph node streaming, GitHub PR fetching & commenting,
live Snyk vulnerability scanning, and isolated Pytest sandbox execution.
"""
import asyncio
import json
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from agent.graph import auditor_graph
from config import AVAILABLE_MODELS, settings
from fixtures.sample_payloads import SAMPLE_PAYLOADS
from github_service import (
    fetch_github_pr,
    format_socratic_pr_comment,
    parse_pr_url,
    post_pr_comment,
    push_remediation_to_github_pr,
)
from snyk_scanner import scan_code_with_snyk

app = FastAPI(
    title="NemoSec & Socratic PR Auditor API",
    description="Dual-Branch DevSecOps & Socratic Code Review Agent powered by Nebius Token Factory & LangGraph",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConfigUpdateRequest(BaseModel):
    nebius_api_key: Optional[str] = None
    nebius_model: Optional[str] = None
    github_token: Optional[str] = None


class FetchPRRequest(BaseModel):
    pr_url: str


class AuditRequest(BaseModel):
    preset_id: Optional[str] = "sql_injection_ledger"
    pr_url: Optional[str] = ""
    file_path: Optional[str] = ""
    code_snippet: Optional[str] = ""
    git_diff: Optional[str] = ""
    snyk_json: Optional[Dict[str, Any]] = None
    model_id: Optional[str] = None
    auto_post_pr_comment: bool = True


class PostPRCommentRequest(BaseModel):
    pr_url: str
    comment_body: str


class ApplyRemediationRequest(BaseModel):
    pr_url: Optional[str] = ""
    file_path: str
    remediated_code: str
    cve_id: str = "CVE-2024-8912"
    snyk_id: str = "SNYK-PYTHON-SQLITE3-612941"
    pre_snyk: Dict[str, Any] = {}
    sandbox_results: Dict[str, Any] = {}
    unified_diff: str = ""
    update_pr_branch_directly: bool = True


class LiveSnykScanRequest(BaseModel):
    code: str
    file_path: str = "demo-vulnerable-app/payment_ledger.py"


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "nemosec-socratic-pr-auditor",
        "nebius_configured": bool(settings.nebius_api_key),
        "github_configured": bool(settings.github_token),
        "active_model": settings.nebius_model,
    }


@app.get("/api/config")
async def get_config():
    return {
        "nebius_configured": bool(settings.nebius_api_key),
        "nebius_base_url": settings.nebius_base_url,
        "nebius_model": settings.nebius_model,
        "github_configured": bool(settings.github_token),
        "default_github_repo": settings.default_github_repo,
        "available_models": AVAILABLE_MODELS,
    }


@app.post("/api/config")
async def update_config(req: ConfigUpdateRequest):
    settings.update(
        nebius_api_key=req.nebius_api_key,
        nebius_model=req.nebius_model,
        github_token=req.github_token,
    )
    return await get_config()


@app.get("/api/presets")
async def list_presets():
    return {
        "presets": list(SAMPLE_PAYLOADS.values()),
    }


@app.post("/api/github/fetch-pr")
async def api_fetch_github_pr(req: FetchPRRequest):
    parsed = parse_pr_url(req.pr_url)
    if not parsed:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub PR URL. Use format https://github.com/owner/repo/pull/1 or owner/repo#1",
        )
    try:
        pr_info = await fetch_github_pr(req.pr_url)
        # Run live Snyk scan on the fetched PR code
        live_snyk = scan_code_with_snyk(
            code=pr_info.get("code_snippet", ""),
            file_path=pr_info.get("target_file", "demo-vulnerable-app/payment_ledger.py"),
        )
        pr_info["snyk_json"] = live_snyk
        pr_info["fetched_live"] = True
        return pr_info
    except Exception as exc:
        # Graceful fallback if the demo PR #1/#2 hasn't been created on GitHub yet
        pull_num = parsed["pull_number"]
        preset_key = "cmd_injection_webhook" if pull_num == 2 else "sql_injection_ledger"
        preset = SAMPLE_PAYLOADS[preset_key]
        live_snyk = scan_code_with_snyk(
            code=preset["code_snippet"],
            file_path=preset["file_path"],
            provided_snyk_json=preset["snyk_json"],
        )
        return {
            "owner": parsed["owner"],
            "repo": parsed["repo"],
            "pull_number": pull_num,
            "html_url": parsed["html_url"],
            "title": preset["name"],
            "state": "open",
            "author": parsed["owner"],
            "head_ref": "feat/merchant-ledger-filter" if pull_num == 1 else "feat/webhook-probe",
            "base_ref": "main",
            "target_file": preset["file_path"],
            "code_snippet": preset["code_snippet"],
            "git_diff": preset["git_diff"],
            "snyk_json": live_snyk,
            "fetched_live": False,
            "fallback_note": f"Loaded local PR #{pull_num} target (`{preset['file_path']}`). Note: {str(exc)[:140]}",
            "existing_comments": [],
        }


@app.post("/api/snyk/scan")
async def api_live_snyk_scan(req: LiveSnykScanRequest):
    return scan_code_with_snyk(
        code=req.code,
        file_path=req.file_path,
        ignore_provided_if_remediated=True,
    )


@app.post("/api/github/post-socratic-comment")
async def api_post_socratic_comment(req: PostPRCommentRequest):
    result = await post_pr_comment(req.pr_url, req.comment_body)
    return result


@app.post("/api/github/apply-remediation")
async def api_apply_remediation(req: ApplyRemediationRequest):
    # 1. Re-scan the remediated code with Snyk to prove the vulnerability is gone (0 issues)
    post_snyk = scan_code_with_snyk(
        code=req.remediated_code,
        file_path=req.file_path,
        ignore_provided_if_remediated=True,
    )

    # 2. Push remediation branch/commit & post Snyk 0-issue verification comment to PR
    push_result = await push_remediation_to_github_pr(
        pr_url=req.pr_url or "",
        file_path=req.file_path,
        remediated_code=req.remediated_code,
        cve_id=req.cve_id,
        snyk_id=req.snyk_id,
        pre_snyk=req.pre_snyk,
        post_snyk=post_snyk,
        sandbox_results=req.sandbox_results,
        unified_diff=req.unified_diff,
        update_pr_branch_directly=req.update_pr_branch_directly,
    )
    return push_result


@app.post("/api/audit/stream")
async def stream_audit(req: AuditRequest):
    """
    SSE endpoint that executes the parallel LangGraph workflow and streams real-time
    node activation & completion events to the React frontend.
    """
    async def event_generator():
        initial_state: Dict[str, Any] = {
            "preset_id": req.preset_id or "sql_injection_ledger",
            "pr_url": req.pr_url or "",
            "file_path": req.file_path or "",
            "code_snippet": req.code_snippet or "",
            "git_diff": req.git_diff or "",
            "snyk_json": req.snyk_json,
            "model_id": req.model_id or settings.nebius_model,
            "auto_post_pr_comment": False,  # Handled asynchronously below for non-blocking SSE
        }

        yield {
            "event": "graph_start",
            "data": json.dumps(
                {
                    "active_nodes": ["ingest_node"],
                    "model_id": initial_state["model_id"],
                    "pr_url": initial_state["pr_url"],
                }
            ),
        }
        await asyncio.sleep(0.15)

        accumulated_state: Dict[str, Any] = dict(initial_state)

        try:
            for chunk in auditor_graph.stream(initial_state, stream_mode="updates"):
                for node_name, node_output in chunk.items():
                    accumulated_state.update(node_output)

                    # Determine next active nodes in DAG for visual transition
                    next_active = []
                    if node_name == "ingest_node":
                        next_active = ["socratic_intent_node", "snyk_scanner_node"]
                    elif node_name == "snyk_scanner_node":
                        next_active = ["sandbox_patcher_node"]
                    elif node_name in ("socratic_intent_node", "sandbox_patcher_node"):
                        next_active = ["finalize_audit_node"]

                    # If Socratic node finished and PR URL is present + auto_post_pr_comment, post to PR
                    if node_name == "socratic_intent_node" and req.pr_url and req.auto_post_pr_comment:
                        comment_md = node_output.get("socratic_analysis", {}).get("formatted_pr_comment", "")
                        if comment_md:
                            pr_comment_res = await post_pr_comment(req.pr_url, comment_md)
                            node_output["pr_comment_result"] = pr_comment_res
                            accumulated_state["pr_comment_result"] = pr_comment_res

                    yield {
                        "event": "node_update",
                        "data": json.dumps(
                            {
                                "completed_node": node_name,
                                "next_active_nodes": next_active,
                                "output": node_output,
                            }
                        ),
                    }
                    await asyncio.sleep(0.2)

            yield {
                "event": "audit_complete",
                "data": json.dumps(accumulated_state),
            }
        except Exception as exc:
            yield {
                "event": "audit_error",
                "data": json.dumps({"error": str(exc)}),
            }

    return EventSourceResponse(event_generator())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

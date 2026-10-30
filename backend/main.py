"""
FastAPI backend for NemoSec & Socratic PR Auditor.
Provides SSE real-time LangGraph node streaming, autonomous same-PR security fix check-in,
Socratic PR commenting, live Snyk vulnerability scanning, and isolated Pytest sandbox execution.
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
    checkin_fix_to_same_pr_and_comment,
    fetch_github_pr,
    parse_pr_url,
    post_pr_comment,
    push_remediation_to_github_pr,
)
from snyk_scanner import scan_code_with_snyk

app = FastAPI(
    title="NemoSec & Socratic PR Auditor API",
    description="Dual-Branch DevSecOps & Socratic Code Review Agent powered by Nebius Token Factory & LangGraph",
    version="2.0.0",
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
    head_ref: Optional[str] = "feat/merchant-ledger-filter"
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
        live_snyk = scan_code_with_snyk(
            code=pr_info.get("code_snippet", ""),
            file_path=pr_info.get("target_file", "demo-vulnerable-app/payment_ledger.py"),
            ignore_provided_if_remediated=True,
        )
        pr_info["snyk_json"] = live_snyk
        pr_info["fetched_live"] = True
        return pr_info
    except Exception as exc:
        pull_num = parsed["pull_number"]
        if pull_num == 3:
            preset_key = "clean_pr_no_vulns"
        elif pull_num == 2:
            preset_key = "cmd_injection_webhook"
        else:
            preset_key = "sql_injection_ledger"

        preset = SAMPLE_PAYLOADS[preset_key]
        live_snyk = scan_code_with_snyk(
            code=preset["code_snippet"],
            file_path=preset["file_path"],
            provided_snyk_json=preset["snyk_json"],
            ignore_provided_if_remediated=True,
        )
        return {
            "owner": parsed["owner"],
            "repo": parsed["repo"],
            "pull_number": pull_num,
            "html_url": parsed["html_url"],
            "title": preset["name"],
            "state": "open",
            "author": parsed["owner"],
            "head_ref": preset.get("head_ref", "feat/merchant-ledger-filter"),
            "base_ref": "main",
            "target_file": preset["file_path"],
            "code_snippet": preset["code_snippet"],
            "git_diff": preset["git_diff"],
            "snyk_json": live_snyk,
            "fetched_live": False,
            "fallback_note": f"Loaded PR #{pull_num} target (`{preset['file_path']}`).",
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
    post_snyk = scan_code_with_snyk(
        code=req.remediated_code,
        file_path=req.file_path,
        ignore_provided_if_remediated=True,
    )
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
    SSE endpoint that executes the parallel LangGraph workflow and automatically:
    - If NO security vulnerability is found: comments the Socratic questions on the PR.
    - If a security vulnerability IS found: checks in the fix as part of the SAME PR
      (with check-in comment confirming the issue is fixed), resolves the Snyk issue
      to 0 vulnerabilities, and posts the Socratic questions + check-in report on the PR.
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
            "auto_post_pr_comment": False,
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
        await asyncio.sleep(0.12)

        accumulated_state: Dict[str, Any] = dict(initial_state)

        try:
            for chunk in auditor_graph.stream(initial_state, stream_mode="updates"):
                for node_name, node_output in chunk.items():
                    accumulated_state.update(node_output)

                    next_active = []
                    if node_name == "ingest_node":
                        next_active = ["socratic_intent_node", "snyk_scanner_node"]
                    elif node_name == "snyk_scanner_node":
                        next_active = ["sandbox_patcher_node"]
                    elif node_name in ("socratic_intent_node", "sandbox_patcher_node"):
                        next_active = ["finalize_audit_node"]

                    # When finalize_audit_node completes, perform the unified PR action automatically!
                    if node_name == "finalize_audit_node":
                        pre_snyk = accumulated_state.get("pre_remediation_snyk", {})
                        post_snyk = accumulated_state.get("post_remediation_snyk", {})
                        vulns = pre_snyk.get("vulnerabilities", [])
                        primary_vuln = vulns[0] if vulns else {}
                        cve_id = primary_vuln.get("cve", "CVE-2024-8912")
                        snyk_id = primary_vuln.get("id", "SNYK-PYTHON-SQLITE3-612941")

                        preset_obj = SAMPLE_PAYLOADS.get(req.preset_id or "", {})
                        head_ref = req.head_ref or preset_obj.get("head_ref", "feat/merchant-ledger-filter")

                        auto_pr_res = await checkin_fix_to_same_pr_and_comment(
                            pr_url=req.pr_url or "",
                            file_path=accumulated_state.get("file_path", "demo-vulnerable-app/payment_ledger.py"),
                            remediated_code=accumulated_state.get("remediated_code", ""),
                            cve_id=cve_id,
                            snyk_id=snyk_id,
                            pre_snyk=pre_snyk,
                            post_snyk=post_snyk,
                            sandbox_results=accumulated_state.get("sandbox_results", {}),
                            unified_diff=accumulated_state.get("unified_diff", ""),
                            socratic_analysis=accumulated_state.get("socratic_analysis", {}),
                            head_ref_hint=head_ref,
                            model_used=initial_state["model_id"],
                        )

                        # Update branch_info and PR comment results in state
                        if accumulated_state.get("branch_info"):
                            accumulated_state["branch_info"]["branch_name"] = auto_pr_res.get("branch_name", head_ref)
                            if auto_pr_res.get("commit_sha"):
                                accumulated_state["branch_info"]["commit_hash"] = auto_pr_res["commit_sha"]
                            if auto_pr_res.get("commit_message"):
                                accumulated_state["branch_info"]["commit_message"] = auto_pr_res["commit_message"]

                        node_output["github_push_result"] = auto_pr_res
                        node_output["pr_comment_result"] = auto_pr_res.get("pr_comment")
                        node_output["branch_info"] = accumulated_state.get("branch_info")
                        accumulated_state["github_push_result"] = auto_pr_res
                        accumulated_state["pr_comment_result"] = auto_pr_res.get("pr_comment")

                        if accumulated_state.get("socratic_analysis") and auto_pr_res.get("pr_comment"):
                            accumulated_state["socratic_analysis"]["formatted_pr_comment"] = (
                                auto_pr_res["pr_comment"].get("body", "")
                            )

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
                    await asyncio.sleep(0.18)

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

"""
LangGraph TypedDict state schema for the dual-branch NemoSec & Socratic PR Auditor.
"""
from typing import Any, Dict, List, Optional, TypedDict


class AuditState(TypedDict, total=False):
    # Input payload
    preset_id: Optional[str]
    pr_url: Optional[str]
    file_path: str
    code_snippet: str
    git_diff: str
    snyk_json: Optional[Dict[str, Any]]
    model_id: str
    auto_post_pr_comment: bool
    auto_push_remediation: bool
    pr_metadata: Optional[Dict[str, Any]]

    # Branch A: Socratic Intent Agent outputs
    socratic_analysis: Dict[str, Any]
    pr_comment_result: Optional[Dict[str, Any]]

    # Branch B: SecOps Auto-Remediation Agent outputs
    pre_remediation_snyk: Dict[str, Any]
    remediated_code: str
    remediation_explanation: str
    unified_diff: str
    sandbox_results: Dict[str, Any]
    post_remediation_snyk: Dict[str, Any]
    branch_info: Dict[str, Any]
    github_push_result: Optional[Dict[str, Any]]

    # Final aggregated status
    audit_summary: Dict[str, Any]

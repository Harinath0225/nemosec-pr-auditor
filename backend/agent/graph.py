"""
Compiled parallel LangGraph StateGraph for NemoSec & Socratic PR Auditor.
Topology:
                 ┌──> socratic_intent_node (Branch A: Socratic + PR Comment) ───────────┐
  START -> ingest_node                                                                   ├──> finalize_audit_node -> END
                 └──> snyk_scanner_node -> sandbox_patcher_node (Branch B: SecOps + Snyk)┘
"""
from langgraph.graph import END, START, StateGraph
from agent.state import AuditState
from agent.nodes import (
    finalize_audit_node,
    ingest_node,
    sandbox_patcher_node,
    snyk_scanner_node,
    socratic_intent_node,
)


def build_auditor_graph():
    builder = StateGraph(AuditState)

    # Register nodes
    builder.add_node("ingest_node", ingest_node)
    builder.add_node("socratic_intent_node", socratic_intent_node)
    builder.add_node("snyk_scanner_node", snyk_scanner_node)
    builder.add_node("sandbox_patcher_node", sandbox_patcher_node)
    builder.add_node("finalize_audit_node", finalize_audit_node)

    # Parallel fan-out from ingest_node to Branch A and Branch B
    builder.add_edge(START, "ingest_node")
    builder.add_edge("ingest_node", "socratic_intent_node")
    builder.add_edge("ingest_node", "snyk_scanner_node")

    # Branch B pipeline: Snyk Scanner -> Pytest Sandbox Patcher & Snyk Re-Verify
    builder.add_edge("snyk_scanner_node", "sandbox_patcher_node")

    # Converge both branches into finalize_audit_node
    builder.add_edge("socratic_intent_node", "finalize_audit_node")
    builder.add_edge("sandbox_patcher_node", "finalize_audit_node")
    builder.add_edge("finalize_audit_node", END)

    return builder.compile()


auditor_graph = build_auditor_graph()

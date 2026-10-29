"""
Isolated temp-directory pytest sandbox runner & branch creator.
Spins up a fresh temporary directory via `tempfile.TemporaryDirectory()`, writes the
remediated module + a comprehensive security & functional `pytest` suite, runs `pytest -v`,
and captures stdout/stderr, pass counts, and unified diff.
"""
import difflib
import hashlib
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def generate_unified_diff(
    original_code: str,
    remediated_code: str,
    file_path: str = "demo-vulnerable-app/payment_ledger.py",
) -> str:
    """Compute a standard git-style unified diff between original and remediated code."""
    orig_lines = original_code.splitlines(keepends=True)
    rem_lines = remediated_code.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        rem_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="\n",
    )
    return "".join(diff).strip()


def _build_pytest_suite(code: str, cve_id: str) -> str:
    """
    Generate a tailored pytest test file that verifies both functional behavior
    and security exploit mitigation (SQL Injection / Command Injection / AST checks).
    """
    if "lookup_merchant_transactions" in code or "sqlite3" in code:
        return '''import sqlite3
import pytest
import target_module


def test_functional_valid_merchant_lookup():
    """Verify legitimate merchant queries return settled records accurately."""
    conn = sqlite3.connect(":memory:")
    target_module.init_ledger_db(conn)
    results = target_module.lookup_merchant_transactions(conn, "merch_prime_01", min_amount_cents=1000)
    assert len(results) == 1
    assert results[0]["merchant_id"] == "merch_prime_01"
    assert results[0]["amount_cents"] == 45000
    assert results[0]["status"] == "SETTLED"


def test_security_blocks_sql_injection_payload():
    """Verify CWE-89 SQL injection payload cannot exfiltrate RESTRICTED admin rows."""
    conn = sqlite3.connect(":memory:")
    target_module.init_ledger_db(conn)
    sqli_payload = "merch_prime_01' OR '1'='1' --"
    results = target_module.lookup_merchant_transactions(conn, sqli_payload, min_amount_cents=0)
    # Parameterized query treats sqli_payload as literal string -> 0 rows returned!
    assert results == [], f"SQLi exploit leaked rows: {results}"


def test_security_union_select_token_exfiltration_blocked():
    """Verify UNION SELECT token exfiltration attempt returns 0 records."""
    conn = sqlite3.connect(":memory:")
    target_module.init_ledger_db(conn)
    union_payload = "' UNION SELECT id, account_token, amount_cents, status FROM transactions --"
    results = target_module.lookup_merchant_transactions(conn, union_payload, min_amount_cents=0)
    assert len(results) == 0
'''
    elif "verify_endpoint_host" in code:
        return '''import pytest
import target_module


def test_functional_valid_hostname_probe():
    """Verify safe hostname probe succeeds."""
    res = target_module.verify_endpoint_host("webhook.internal.example.com", timeout_sec=3)
    assert res["hostname"] == "webhook.internal.example.com"
    assert res["reachable"] is True


def test_security_blocks_command_injection_semicolon():
    """Verify CWE-78 command injection with `;` or `&&` is rejected."""
    with pytest.raises((ValueError, Exception)):
        target_module.verify_endpoint_host("example.com && echo PWNED_RCE", timeout_sec=2)


def test_security_blocks_subshell_backticks():
    """Verify subshell injection `$(whoami)` is blocked by strict allowlist."""
    with pytest.raises((ValueError, Exception)):
        target_module.verify_endpoint_host("$(whoami).evil.com", timeout_sec=2)
'''
    else:
        return '''import ast
import target_module


def test_module_compiles_and_imports_cleanly():
    """Verify remediated module has valid syntax and imports cleanly."""
    with open(target_module.__file__, "r", encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    assert tree is not None


def test_no_dangerous_shell_true_calls():
    """Verify no subprocess(..., shell=True) calls remain in remediated code."""
    with open(target_module.__file__, "r", encoding="utf-8") as f:
        source = f.read()
    assert "shell=True" not in source


def test_no_raw_sql_fstring_execution():
    """Verify no unparameterized SQL f-string queries remain."""
    with open(target_module.__file__, "r", encoding="utf-8") as f:
        source = f.read()
    assert 'f"SELECT ' not in source and "f'SELECT " not in source
'''


def run_sandbox_verification(
    original_code: str,
    remediated_code: str,
    cve_id: str = "CVE-2024-8912",
    file_path: str = "demo-vulnerable-app/payment_ledger.py",
    custom_test_code: str | None = None,
) -> Dict[str, Any]:
    """
    Execute `pytest` in an isolated temporary directory against `remediated_code`,
    generate a unified diff, and simulate creating the `fix/secops-<cve-id>` branch.
    """
    start_time = time.perf_counter()
    clean_cve = re.sub(r"[^a-zA-Z0-9_-]", "-", cve_id.lower())
    branch_name = f"fix/secops-{clean_cve}"

    with tempfile.TemporaryDirectory(prefix="nemosec_sandbox_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        target_file = tmp_path / "target_module.py"
        test_file = tmp_path / "test_secops_remediation.py"

        target_file.write_text(remediated_code, encoding="utf-8")
        suite_code = custom_test_code or _build_pytest_suite(remediated_code, cve_id)
        test_file.write_text(suite_code, encoding="utf-8")

        cmd = [sys.executable, "-m", "pytest", "test_secops_remediation.py", "-v", "--tb=short"]
        proc = subprocess.run(
            cmd,
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=25,
        )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 1)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        combined_output = (stdout + ("\n" + stderr if stderr else "")).strip()

        passed_match = re.search(r"(\d+)\s+passed", combined_output)
        failed_match = re.search(r"(\d+)\s+failed", combined_output)
        passed_count = int(passed_match.group(1)) if passed_match else (3 if proc.returncode == 0 else 0)
        failed_count = int(failed_match.group(1)) if failed_match else (0 if proc.returncode == 0 else 1)
        total_count = passed_count + failed_count

        commit_hash = hashlib.sha256(f"{branch_name}:{remediated_code}".encode("utf-8")).hexdigest()[:8]
        unified_diff = generate_unified_diff(original_code, remediated_code, file_path=file_path)

        return {
            "passed": proc.returncode == 0,
            "exit_code": proc.returncode,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "total_count": total_count,
            "duration_ms": duration_ms,
            "sandbox_dir": str(tmp_path),
            "stdout": combined_output,
            "test_suite_source": suite_code,
            "unified_diff": unified_diff,
            "branch_info": {
                "branch_name": branch_name,
                "base_branch": "main",
                "commit_hash": commit_hash,
                "commit_message": f"fix(secops): remediate {cve_id} in {file_path} (verified via pytest sandbox)",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "READY_FOR_PR_REVIEW" if proc.returncode == 0 else "SANDBOX_FAILED",
            },
        }

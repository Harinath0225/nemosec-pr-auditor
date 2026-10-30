"""
Built-in vulnerable and clean PR presets for 1-click hackathon demo and GitHub PR audit testing.
"""
from typing import Dict, Any

SAMPLE_PAYLOADS: Dict[str, Dict[str, Any]] = {
    "sql_injection_ledger": {
        "id": "sql_injection_ledger",
        "name": "PR #1 (Vulnerable): Payment Ledger Filter — Auto-Fix in Same PR + Ask Socratic Questions",
        "pr_url": "https://github.com/Harinath0225/nemosec-pr-auditor/pull/1",
        "head_ref": "feat/merchant-ledger-filter",
        "file_path": "demo-vulnerable-app/payment_ledger.py",
        "description": "Contains SQL Injection (CVE-2024-8912). Agent automatically checks in the fix on the same PR branch, resolves Snyk to 0 issues, and posts Socratic questions.",
        "code_snippet": '''"""
Microservice ledger lookup module (Demo Target for GitHub PR Audit).
Contains an intentional SQL Injection vulnerability (CWE-89 / SNYK-PYTHON-SQLITE3-612941)
introduced during a performance-caching refactor.
"""
import sqlite3
from typing import Dict, Any, List


def init_ledger_db(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            merchant_id TEXT NOT NULL,
            account_token TEXT NOT NULL,
            amount_cents INTEGER NOT NULL,
            status TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        "INSERT INTO transactions (merchant_id, account_token, amount_cents, status) VALUES (?, ?, ?, ?)",
        ("merch_prime_01", "tok_live_9981", 45000, "SETTLED"),
    )
    cursor.execute(
        "INSERT INTO transactions (merchant_id, account_token, amount_cents, status) VALUES (?, ?, ?, ?)",
        ("merch_internal_admin", "tok_secret_admin", 999900, "RESTRICTED"),
    )
    conn.commit()


def lookup_merchant_transactions(
    conn: sqlite3.Connection,
    merchant_id: str,
    min_amount_cents: int = 0,
) -> List[Dict[str, Any]]:
    """
    Fetch settled transactions for a merchant above a minimum threshold.
    WARNING: Vulnerable f-string SQL query construction introduced in PR!
    """
    cursor = conn.cursor()
    # VULNERABLE: Direct string interpolation allows SQL Injection (CWE-89)
    query = (
        f"SELECT id, merchant_id, amount_cents, status FROM transactions "
        f"WHERE merchant_id = '{merchant_id}' AND amount_cents >= {min_amount_cents} "
        f"AND status = 'SETTLED'"
    )
    cursor.execute(query)
    rows = cursor.fetchall()
    return [
        {
            "id": row[0],
            "merchant_id": row[1],
            "amount_cents": row[2],
            "status": row[3],
        }
        for row in rows
    ]
''',
        "git_diff": """--- a/demo-vulnerable-app/payment_ledger.py
+++ b/demo-vulnerable-app/payment_ledger.py
@@ -31,14 +31,15 @@ def lookup_merchant_transactions(
     conn: sqlite3.Connection,
     merchant_id: str,
     min_amount_cents: int = 0,
 ) -> List[Dict[str, Any]]:
     cursor = conn.cursor()
-    cursor.execute(
-        "SELECT id, merchant_id, amount_cents, status FROM transactions WHERE merchant_id = ?",
-        (merchant_id,),
-    )
+    # Fast-path query builder with dynamic min_amount_cents filter
+    query = (
+        f"SELECT id, merchant_id, amount_cents, status FROM transactions "
+        f"WHERE merchant_id = '{merchant_id}' AND amount_cents >= {min_amount_cents} "
+        f"AND status = 'SETTLED'"
+    )
+    cursor.execute(query)
     rows = cursor.fetchall()
     return [
         {"id": row[0], "merchant_id": row[1], "amount_cents": row[2], "status": row[3]}
         for row in rows
     ]""",
        "snyk_json": {
            "ok": False,
            "total_issues": 1,
            "vulnerabilities": [
                {
                    "id": "SNYK-PYTHON-SQLITE3-612941",
                    "cve": "CVE-2024-8912",
                    "cwe": ["CWE-89"],
                    "title": "SQL Injection (Unsanitized String Interpolation in SQL Query)",
                    "severity": "critical",
                    "cvssScore": 9.8,
                    "file_path": "demo-vulnerable-app/payment_ledger.py",
                    "line_number": 45,
                    "vulnerable_line": "query = f\"SELECT id, merchant_id, amount_cents, status FROM transactions WHERE merchant_id = '{merchant_id}' ...\"",
                    "description": "User-supplied `merchant_id` is interpolated directly into a raw SQL query string via Python f-string formatting. An attacker supplying `' OR '1'='1' --` bypasses tenant isolation and status filters to dump RESTRICTED admin records.",
                    "remediation_advice": "Use parameterized SQL queries with `?` placeholders and pass `(merchant_id, int(min_amount_cents))` as a parameter tuple to `cursor.execute()`.",
                }
            ],
        },
        "remediated_code": '''"""
Microservice ledger lookup module (Demo Target for GitHub PR Audit).
Remediated by NemoSec SecOps Agent: Parameterized SQL queries & strict type validation.
"""
import sqlite3
from typing import Dict, Any, List


def init_ledger_db(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            merchant_id TEXT NOT NULL,
            account_token TEXT NOT NULL,
            amount_cents INTEGER NOT NULL,
            status TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        "INSERT INTO transactions (merchant_id, account_token, amount_cents, status) VALUES (?, ?, ?, ?)",
        ("merch_prime_01", "tok_live_9981", 45000, "SETTLED"),
    )
    cursor.execute(
        "INSERT INTO transactions (merchant_id, account_token, amount_cents, status) VALUES (?, ?, ?, ?)",
        ("merch_internal_admin", "tok_secret_admin", 999900, "RESTRICTED"),
    )
    conn.commit()


def lookup_merchant_transactions(
    conn: sqlite3.Connection,
    merchant_id: str,
    min_amount_cents: int = 0,
) -> List[Dict[str, Any]]:
    """
    Fetch settled transactions for a merchant above a minimum threshold.
    REMEDIATED: Uses DB-API 2.0 parameterized query placeholders (?) to prevent CWE-89 SQL Injection.
    """
    if not isinstance(merchant_id, str) or not merchant_id.strip():
        raise ValueError("Invalid merchant_id")
    safe_min_amount = int(min_amount_cents)

    cursor = conn.cursor()
    query = (
        "SELECT id, merchant_id, amount_cents, status FROM transactions "
        "WHERE merchant_id = ? AND amount_cents >= ? "
        "AND status = 'SETTLED'"
    )
    cursor.execute(query, (merchant_id, safe_min_amount))
    rows = cursor.fetchall()
    return [
        {
            "id": row[0],
            "merchant_id": row[1],
            "amount_cents": row[2],
            "status": row[3],
        }
        for row in rows
    ]
''',
    },
    "cmd_injection_webhook": {
        "id": "cmd_injection_webhook",
        "name": "PR #2 (Vulnerable): Webhook Diagnostic Probe — Auto-Fix in Same PR + Ask Socratic Questions",
        "pr_url": "https://github.com/Harinath0225/nemosec-pr-auditor/pull/2",
        "head_ref": "feat/webhook-probe",
        "file_path": "demo-vulnerable-app/webhook_diagnostics.py",
        "description": "Contains OS Command Injection (CVE-2024-9401). Agent automatically checks in the fix on the same PR branch, resolves Snyk to 0 issues, and posts Socratic questions.",
        "code_snippet": '''"""
Network diagnostic utility for webhook delivery verification.
Contains an intentional OS Command Injection vulnerability (CWE-78 / SNYK-PYTHON-SUBPROCESS-704821).
"""
import subprocess
from typing import Dict, Any


def verify_endpoint_host(hostname: str, timeout_sec: int = 2) -> Dict[str, Any]:
    """
    Run a quick diagnostic check on a target webhook hostname.
    WARNING: Uses shell=True with unsanitized hostname string!
    """
    cmd = f"echo Probing {hostname} && echo STATUS_OK"
    output = subprocess.check_output(
        cmd,
        shell=True,
        text=True,
        timeout=timeout_sec,
    )
    return {
        "hostname": hostname,
        "reachable": "STATUS_OK" in output,
        "raw_output": output.strip(),
    }
''',
        "git_diff": """--- a/demo-vulnerable-app/webhook_diagnostics.py
+++ b/demo-vulnerable-app/webhook_diagnostics.py
@@ -1,12 +1,18 @@
 import subprocess
 from typing import Dict, Any
 
 def verify_endpoint_host(hostname: str, timeout_sec: int = 2) -> Dict[str, Any]:
-    return {"hostname": hostname, "reachable": True}
+    cmd = f"echo Probing {hostname} && echo STATUS_OK"
+    output = subprocess.check_output(
+        cmd,
+        shell=True,
+        text=True,
+        timeout=timeout_sec,
+    )
+    return {
+        "hostname": hostname,
+        "reachable": "STATUS_OK" in output,
+        "raw_output": output.strip(),
+    }""",
        "snyk_json": {
            "ok": False,
            "total_issues": 1,
            "vulnerabilities": [
                {
                    "id": "SNYK-PYTHON-SUBPROCESS-704821",
                    "cve": "CVE-2024-9401",
                    "cwe": ["CWE-78"],
                    "title": "OS Command Injection via subprocess with shell=True",
                    "severity": "critical",
                    "cvssScore": 9.6,
                    "file_path": "demo-vulnerable-app/webhook_diagnostics.py",
                    "line_number": 14,
                    "vulnerable_line": "output = subprocess.check_output(cmd, shell=True, text=True, timeout=timeout_sec)",
                    "description": "Passing an f-string containing `hostname` into `subprocess.check_output(..., shell=True)` allows attackers to inject shell metacharacters (`;`, `&&`, `|`) to execute arbitrary OS commands.",
                    "remediation_advice": "Validate `hostname` against a strict allowlist regex (`^[a-zA-Z0-9.-]+$`) and invoke `subprocess.run` with an argument list and `shell=False`.",
                }
            ],
        },
        "remediated_code": '''"""
Network diagnostic utility for webhook delivery verification.
Remediated by NemoSec SecOps Agent: Strict hostname allowlist + shell=False token list.
"""
import re
import sys
import subprocess
from typing import Dict, Any

HOSTNAME_ALLOWLIST_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


def verify_endpoint_host(hostname: str, timeout_sec: int = 2) -> Dict[str, Any]:
    """
    Run a safe diagnostic check on a target webhook hostname.
    REMEDIATED: Rejects shell metacharacters and executes without a shell (shell=False).
    """
    if not isinstance(hostname, str) or not HOSTNAME_ALLOWLIST_RE.match(hostname):
        raise ValueError(f"Blocked unsafe hostname format: {hostname!r}")

    proc = subprocess.run(
        [sys.executable, "-c", "import sys; print(f'Probing {sys.argv[1]} STATUS_OK')", hostname],
        shell=False,
        capture_output=True,
        text=True,
        timeout=int(timeout_sec),
        check=True,
    )
    output = proc.stdout.strip()
    return {
        "hostname": hostname,
        "reachable": "STATUS_OK" in output,
        "raw_output": output,
    }
''',
    },
    "clean_pr_no_vulns": {
        "id": "clean_pr_no_vulns",
        "name": "PR #3 (Clean / 0 Vulnerabilities): Parameterized Ledger Query — Comment Socratic Questions Only",
        "pr_url": "https://github.com/Harinath0225/nemosec-pr-auditor/pull/3",
        "head_ref": "feat/safe-ledger-pagination",
        "file_path": "demo-vulnerable-app/payment_ledger.py",
        "description": "Clean PR with 0 Snyk vulnerabilities. Agent verifies 0 issues and comments Socratic architectural questions on the PR without modifying code.",
        "code_snippet": '''"""
Clean parameterized ledger query module with zero security vulnerabilities.
"""
import sqlite3
from typing import Dict, Any, List


def lookup_merchant_transactions(
    conn: sqlite3.Connection,
    merchant_id: str,
    min_amount_cents: int = 0,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Fetch settled transactions using parameterized placeholders (0 Snyk issues).
    """
    cursor = conn.cursor()
    query = (
        "SELECT id, merchant_id, amount_cents, status FROM transactions "
        "WHERE merchant_id = ? AND amount_cents >= ? AND status = 'SETTLED' "
        "LIMIT ?"
    )
    cursor.execute(query, (merchant_id, int(min_amount_cents), int(limit)))
    rows = cursor.fetchall()
    return [
        {"id": row[0], "merchant_id": row[1], "amount_cents": row[2], "status": row[3]}
        for row in rows
    ]
''',
        "git_diff": """--- a/demo-vulnerable-app/payment_ledger.py
+++ b/demo-vulnerable-app/payment_ledger.py
@@ -10,10 +10,12 @@ def lookup_merchant_transactions(
     conn: sqlite3.Connection,
     merchant_id: str,
     min_amount_cents: int = 0,
+    limit: int = 50,
 ) -> List[Dict[str, Any]]:
     cursor = conn.cursor()
     query = (
         "SELECT id, merchant_id, amount_cents, status FROM transactions "
-        "WHERE merchant_id = ? AND amount_cents >= ? AND status = 'SETTLED'"
+        "WHERE merchant_id = ? AND amount_cents >= ? AND status = 'SETTLED' "
+        "LIMIT ?"
     )
-    cursor.execute(query, (merchant_id, int(min_amount_cents)))
+    cursor.execute(query, (merchant_id, int(min_amount_cents), int(limit)))""",
        "snyk_json": {
            "ok": True,
            "total_issues": 0,
            "vulnerabilities": [],
        },
        "remediated_code": "",
    },
}

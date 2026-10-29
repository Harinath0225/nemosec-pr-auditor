"""
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

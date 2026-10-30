"""
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

"""
Network diagnostic utility for webhook delivery verification (Demo Target for GitHub PR Audit).
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

# backend/database.py

import os
from typing import List, Dict, Any
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
ROOT_DIR = Path(__file__).resolve().parents[1]
env_path = ROOT_DIR / ".env"
load_dotenv(env_path)

# -------------------------------------------------
# SIMPLE IN-MEMORY STORAGE (ADAPT IF YOU USE REAL DB)
# -------------------------------------------------

# You may already have these; keep your existing implementations if so.
_nmap_results: Dict[str, List[Dict[str, Any]]] = {}
_scan_metadata: Dict[str, Dict[str, Any]] = {}
_layer2_results: Dict[str, Dict[str, Any]] = {}


def save_nmap_results(rows: List[Dict[str, Any]], scan_type: str = "Normal") -> None:
    _nmap_results[scan_type] = rows


def get_nmap_results(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    return _nmap_results.get(scan_type, [])


def save_scan_metadata(meta: Dict[str, Any], scan_type: str | None = None) -> None:
    st = scan_type or meta.get("scan_type", "Normal")
    _scan_metadata[st] = meta


def get_scan_metadata(scan_type: str = "Normal") -> Dict[str, Any]:
    return _scan_metadata.get(scan_type, {"scan_type": scan_type})


def save_layer2_result(result: Dict[str, Any], scan_type: str | None = None) -> None:
    st = scan_type or result.get("scan_type", "Normal")
    _layer2_results[st] = result


def _get_layer2(scan_type: str = "Normal") -> Dict[str, Any]:
    return _layer2_results.get(scan_type, {})


def get_vulnerabilities(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Return flat vulnerability list from Layer‑2 result.
    Expects Layer‑2 to store under key 'vulnerabilities'.
    """
    l2 = _get_layer2(scan_type)
    vulns = l2.get("vulnerabilities", [])
    return vulns if isinstance(vulns, list) else []


def get_risk_summary(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Return risk summary from Layer‑2 result.
    Adjust key if your pipeline uses a different name.
    """
    l2 = _get_layer2(scan_type)
    summary = l2.get("summary", [])
    return summary if isinstance(summary, list) else []


# -------------------------------------------------
# OPENROUTER KEY ACCESSOR
# -------------------------------------------------

def get_openrouter_key() -> str | None:
    """
    Return the OpenRouter API key from environment.
    Requires OPENROUTER_API_KEY in .env at project root.
    """
    return os.getenv("OPENROUTER_API_KEY")

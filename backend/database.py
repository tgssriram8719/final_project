# backend/database.py

from typing import List, Dict, Any
import os

# --------- IN-MEMORY STORES (TEMPORARY) ---------

# Nmap scan rows per scan_type
_nmap_results: Dict[str, List[Dict[str, Any]]] = {}

# Last scan metadata
_scan_metadata: Dict[str, Any] = {}

# Layer 2 processed results (can hold multiple scans)
_layer2_results: List[Dict[str, Any]] = []


# --------- LAYER 1: NMAP RESULTS ---------

def save_nmap_results(rows: List[Dict[str, Any]], scan_type: str = "Normal") -> None:
    """
    Store flat Nmap rows (output of layer1_scanner.main.run_scan).
    """
    _nmap_results[scan_type] = rows


def get_nmap_results(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Return Nmap rows for given scan_type.
    """
    return _nmap_results.get(scan_type, [])


def save_scan_metadata(meta: Dict[str, Any]) -> None:
    """
    Store basic scan metadata (scan_type, target, timestamp, etc.).
    """
    global _scan_metadata
    _scan_metadata = meta


def get_scan_metadata(scan_type: str = "Normal") -> Dict[str, Any]:
    """
    Metadata endpoint used by dashboard.data_loader.load_scan_metadata.
    """
    if not _scan_metadata:
        return {"scan_type": scan_type}
    return _scan_metadata


# --------- LAYER 2: VULNERABILITIES & RISK ---------

def save_layer2_result(result: Dict[str, Any]) -> None:
    """
    Save one full Layer 2 pipeline output document.
    """
    _layer2_results.append(result)


def get_vulnerabilities(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Return a flat list of vulnerabilities across all Layer 2 results.
    Used by /vulnerabilities for dashboard pages.
    """
    vulns: List[Dict[str, Any]] = []
    for r in _layer2_results:
        items = (
            r.get("vulnerabilities")
            or r.get("normalized_vulnerabilities")
            or []
        )
        vulns.extend(items)
    return vulns


def get_risk_summary(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Return a list of summary/risk objects per asset or scan.
    Used by /risk/summary for risk_analysis.py & threat_summary.py.
    """
    summaries: List[Dict[str, Any]] = []
    for r in _layer2_results:
        if "summary" in r:
            summaries.append(r["summary"])
        elif "risk_summary" in r:
            summaries.append(r["risk_summary"])
    return summaries


# --------- LAYER 3: AI CONFIG ---------

def get_openrouter_key() -> str:
    """
    Provide OpenRouter API key to Layer 3 CVESummarizer.
    """
    return os.getenv("OPENROUTER_API_KEY", "")

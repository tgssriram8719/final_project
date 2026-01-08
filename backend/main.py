# backend/main.py

from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# ---------- IMPORT LOWER LAYERS ----------

# Layer 1 – real Nmap scanner
from layer1_scanner import main as l1_main  # exposes run_scan()

# Layer 2 – vulnerability & risk pipeline
from layer2_pipeline import pipeline as l2_pipeline  # exposes run_pipeline()

# Layer 3 – AI CVE summarizer
try:
    from layer3_ai.Final_Layer3 import (
        CVESummarizer,
        detect_products,
        generate_fixes,
        ai_predict_epss,
    )
except ImportError:
    CVESummarizer = None
    detect_products = None
    generate_fixes = None
    ai_predict_epss = None

from . import database  # backend/database.py


# ---------- FASTAPI APP ----------

app = FastAPI(title="Cyber Risk Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev; restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================
# LAYER 1 + LAYER 2 – SCAN CONTROL
# =====================================================

@app.post("/scan/run")
def run_scan(
    scan_type: str = "Normal",
    target: str = "scanme.nmap.org",
) -> Dict[str, Any]:
    """
    Trigger Layer 1 Nmap scan, then immediately run Layer 2 pipeline.
    Returns basic status + counts so the dashboard can show a toast.
    """

    # -------- Layer 1: Nmap --------
    try:
        rows: List[Dict[str, Any]] = l1_main.run_scan(
            scan_type=scan_type,
            target=target,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Layer1 error: {e}")

    # Save raw Layer 1 rows + metadata
    database.save_nmap_results(rows, scan_type=scan_type)
    database.save_scan_metadata(
        {
            "scan_type": scan_type,
            "target": target,
        }
    )

    # -------- Layer 2: vulnerability & risk --------
    # Build payload for Layer 2 pipeline from Nmap rows
    payload = {
        "scan_type": scan_type,
        "target": target,
        "rows": rows,
    }

    try:
        l2_result = l2_pipeline.run_pipeline(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Layer2 error: {e}")

    if l2_result.get("status") != "success":
        # Still return Layer‑1 result, but indicate L2 failed
        return {
            "status": "partial",
            "rows": len(rows),
            "layer2": l2_result,
        }

    # Persist Layer 2 output so /vulnerabilities & /risk/summary have data
    database.save_layer2_result(l2_result)

    return {
        "status": "ok",
        "rows": len(rows),
        "layer2": {
            "vulns": len(l2_result.get("vulnerabilities", [])),
        },
    }


@app.get("/nmap/results")
def get_nmap_results(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Raw Nmap rows for dashboard Nmap tab.
    """
    return database.get_nmap_results(scan_type=scan_type)


@app.get("/scan/metadata")
def get_scan_metadata(scan_type: str = "Normal") -> Dict[str, Any]:
    """
    Basic scan metadata (type, target, etc.).
    """
    return database.get_scan_metadata(scan_type=scan_type)


# =====================================================
# LAYER 2 – READ‑ONLY ENDPOINTS FOR DASHBOARD
# =====================================================

@app.post("/layer2/scan")
def process_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Optional direct Layer‑2 trigger if you ever need it from outside.
    """
    try:
        result = l2_pipeline.run_pipeline(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Layer2 error: {e}")

    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result)

    database.save_layer2_result(result)
    return result


@app.get("/vulnerabilities")
def get_vulnerabilities(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Flat vulnerability list for Vulnerabilities, Vulnerability Insights,
    Risk Analysis and AI Analyst tabs.
    """
    return database.get_vulnerabilities(scan_type=scan_type)


@app.get("/risk/summary")
def get_risk_summary(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Risk summary objects for Threat Summary and Risk Analysis tabs.
    """
    return database.get_risk_summary(scan_type=scan_type)


# =====================================================
# LAYER 3 – AI CVE SUMMARIES
# =====================================================

@app.post("/layer3/cve/summary")
def cve_ai_summary(cve: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich one CVE record with AI explanation + EPSS‑style score.
    """
    if CVESummarizer is None or ai_predict_epss is None:
        raise HTTPException(
            status_code=500,
            detail="Layer3 AI module not available.",
        )

    api_key = database.get_openrouter_key()
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="OPENROUTER_API_KEY not configured.",
        )

    summarizer = CVESummarizer(api_key=api_key, model="openai/gpt-4o-mini")

    try:
        ai_text = summarizer.summarize(cve)
    except Exception as e:
        ai_text = {}
        print(f"CVESummarizer error: {e}")

    epss = ai_predict_epss(cve.get("cvss_vector"))

    context_for_products = ai_text if ai_text else cve
    affected_products = (
        detect_products(context_for_products) if detect_products else []
    )
    fixes = generate_fixes(affected_products) if generate_fixes else []

    return {
        "cve_id": cve.get("cve_id"),
        "cvss_vector": cve.get("cvss_vector"),
        "severity": cve.get("severity"),
        "cvss_score": cve.get("cvss_score"),
        "simple_summary": ai_text.get("simple_summary", "")
        if isinstance(ai_text, dict)
        else "",
        "simple_description": ai_text.get("simple_description", "")
        if isinstance(ai_text, dict)
        else "",
        "affected_products": affected_products,
        "affected_assets": cve.get("affected_assets", []),
        "fixes": fixes,
        "epss_score": epss.get("score") if isinstance(epss, dict) else None,
        "epss_30d_prediction": epss.get("predicted_30d")
        if isinstance(epss, dict)
        else None,
    }

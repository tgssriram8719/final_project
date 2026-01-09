# backend/main.py

from typing import List, Dict, Any
import json
import requests

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# ---------- IMPORT LOWER LAYERS ----------

# Layer 1 – Nmap scanner
from layer1_scanner import main as l1_main  # exposes run_scan()

# Layer 2 – vulnerability & risk pipeline
from layer2_pipeline import pipeline as l2_pipeline  # exposes run_pipeline()

# Layer 3 – AI CVE summarizer + helpers
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
    End-to-end scan flow:

    1) Layer 1: live Nmap scan (service + version, plus any vuln script data).
    2) Layer 2: use intel tools (NVD, Vulners, CISA KEV, VirusTotal, Shodan)
       via layer2_pipeline.run_pipeline to map services/versions to known CVEs.
    3) Save all results so dashboard endpoints (/nmap/results, /vulnerabilities,
       /risk/summary) can serve data to all tabs.
    """

    # -------- Layer 1 --------
    try:
        rows: List[Dict[str, Any]] = l1_main.run_scan(
            scan_type=scan_type,
            target=target,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Layer1 error: {e}")

    # Save raw Nmap rows + metadata for Nmap tab and Overview
    database.save_nmap_results(rows, scan_type=scan_type)
    database.save_scan_metadata(
        {
            "scan_type": scan_type,
            "target": target,
        }
    )

    # -------- Layer 2 --------
    payload = {
        "scan_type": scan_type,
        "target": target,
        "rows": rows,
    }

    try:
        l2_result = l2_pipeline.run_pipeline(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Layer2 error: {e}")

    # DEBUG
    print("==== LAYER 2 RESULT DEBUG ====")
    try:
        print("L2_RESULT_KEYS:", list(l2_result.keys()))
    except Exception:
        print("L2_RESULT_KEYS: <unable to list keys>")
    try:
        print("L2_VULNS_LEN:", len(l2_result.get("vulnerabilities", [])))
    except Exception:
        print("L2_VULNS_LEN: <error computing length>")

    if l2_result.get("status") != "success":
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


# =====================================================
# LAYER 1 – READ‑ONLY ENDPOINTS FOR DASHBOARD
# =====================================================

@app.get("/nmap/results")
def get_nmap_results(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """Raw Nmap rows for Nmap tab and any Layer‑3 use."""
    return database.get_nmap_results(scan_type=scan_type)


@app.get("/scan/metadata")
def get_scan_metadata(scan_type: str = "Normal") -> Dict[str, Any]:
    """Scan metadata (type, target, etc.) for Overview tab."""
    return database.get_scan_metadata(scan_type=scan_type)


# =====================================================
# LAYER 2 – READ‑ONLY ENDPOINTS FOR DASHBOARD
# =====================================================

@app.post("/layer2/scan")
def process_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Optional direct Layer‑2 trigger, if ever needed externally."""
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
    Flat vulnerability list used by:
    - Vulnerabilities tab
    - Vulnerability Insights tab
    - AI Analyst tab
    """
    return database.get_vulnerabilities(scan_type=scan_type)


@app.get("/risk/summary")
def get_risk_summary(scan_type: str = "Normal") -> List[Dict[str, Any]]:
    """
    Risk summary used by:
    - Threat Summary tab
    - Risk Analysis tab
    """
    return database.get_risk_summary(scan_type=scan_type)


# =====================================================
# LAYER 3 – AI CVE SUMMARIES
# =====================================================

@app.post("/layer3/cve/summary")
def cve_ai_summary(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich one CVE with AI explanation + EPSS-style prediction."""
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


# =====================================================
# LAYER 3 – AI CHAT ANALYST
# =====================================================

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"


@app.post("/layer3/chat")
def layer3_chat(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    General AI security analyst chat.

    Expects JSON body:
    {
        "question": "text from user",
        "scan_type": "Normal"   # optional
    }
    Uses current scan's vulnerabilities + risk summary as context.
    """
    question = body.get("question", "")
    scan_type = body.get("scan_type", "Normal")

    if not question or not question.strip():
        raise HTTPException(status_code=400, detail="Question is required")

    # Context from DB
    vulns = database.get_vulnerabilities(scan_type=scan_type)
    risk = database.get_risk_summary(scan_type=scan_type)

    # Load API key
    api_key = database.get_openrouter_key()
    print("DEBUG OPENROUTER KEY PRESENT:", bool(api_key))
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="OPENROUTER_API_KEY not configured.",
        )

    system_prompt = (
        "You are an AI security analyst for a vulnerability management dashboard. "
        "Explain risks, prioritize remediation, and answer questions based on the "
        "given vulnerabilities and risk summary. Be concise and clear."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                "Here is the current scan context.\n\n"
                f"VULNERABILITIES JSON:\n{json.dumps(vulns)[:6000]}\n\n"
                f"RISK_SUMMARY JSON:\n{json.dumps(risk)[:4000]}\n\n"
                f"USER QUESTION:\n{question}"
            ),
        },
    ]

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "openai/gpt-4o-mini",
        "messages": messages,
    }

    try:
        r = requests.post(
            OPENROUTER_ENDPOINT, headers=headers, json=payload, timeout=60
        )
        print("OPENROUTER STATUS:", r.status_code)
        print("OPENROUTER BODY:", r.text[:1000])
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print("OPENROUTER ERROR:", repr(e))
        raise HTTPException(status_code=502, detail=f"AI chat error: {e}")

    return {"answer": content}

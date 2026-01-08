import tempfile

import streamlit as st

from dashboard.data_loader import load, load_scan_metadata
from pdf_export import generate_executive_pdf


def run(context=None):
    scan_type = (context or {}).get("scan_type", "Normal")

    st.subheader("Export Executive PDF Report")

    # Load data needed for the summary
    meta = load_scan_metadata(scan_type)
    nmap_df = load("/nmap/results", scan_type)
    vuln_df = load("/vulnerabilities", scan_type)
    risk_df = load("/risk/summary", scan_type)

    # Compute simple stats
    hosts = (
        int(nmap_df["host"].nunique())
        if nmap_df is not None and not nmap_df.empty and "host" in nmap_df.columns
        else 0
    )
    vulns = len(vuln_df) if vuln_df is not None and not vuln_df.empty else 0

    risk_level = "Unknown"
    threat_score = 0

    if risk_df is not None and not risk_df.empty:
        if "overall_risk" in risk_df.columns:
            levels = risk_df["overall_risk"].astype(str).str.upper()
            if "CRITICAL" in levels.values:
                risk_level = "Critical"
            elif "HIGH" in levels.values:
                risk_level = "High"
            elif "MEDIUM" in levels.values:
                risk_level = "Medium"
            elif "LOW" in levels.values:
                risk_level = "Low"

        if "risk_score" in risk_df.columns:
            try:
                threat_score = int(risk_df["risk_score"].astype(float).mean())
            except Exception:
                threat_score = 0

    summary = {
        "scan_type": meta.get("scan_type", scan_type),
        "hosts": hosts,
        "vulns": vulns,
        "risk_level": risk_level,
        "threat_score": threat_score,
    }

    st.markdown("### Summary to export")
    st.json(summary)

    st.markdown("---")

    if st.button("Generate Executive PDF"):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            generate_executive_pdf(summary, tmp.name)
            tmp.seek(0)
            pdf_bytes = tmp.read()

        st.download_button(
            label="Download Executive Summary PDF",
            data=pdf_bytes,
            file_name="executive_summary.pdf",
            mime="application/pdf",
        )

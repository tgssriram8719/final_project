import streamlit as st

from dashboard.data_loader import load


def run(context=None):
    scan_type = (context or {}).get("scan_type", "Normal")

    st.subheader("Threat Summary")

    risk_df = load("/risk/summary", scan_type)
    vulns_df = load("/vulnerabilities", scan_type)

    if getattr(risk_df, "empty", True) and getattr(vulns_df, "empty", True):
        st.info("No data available for summary")
        return

    st.markdown("### High‑Level Overview")

    if not getattr(risk_df, "empty", True):
        try:
            high_risk = risk_df[
                risk_df["overall_risk"].astype(str).str.upper() == "HIGH"
            ]
            st.markdown(f"- Assets with **HIGH** risk: {len(high_risk)}")
        except Exception:
            pass

    if not getattr(vulns_df, "empty", True):
        try:
            critical = vulns_df[
                vulns_df["severity"].astype(str).str.upper() == "CRITICAL"
            ]
            st.markdown(f"- Critical vulnerabilities: {len(critical)}")
        except Exception:
            pass

    st.markdown(
        "Use the Vulnerability Insights and Risk Analysis tabs for detailed breakdowns."
    )

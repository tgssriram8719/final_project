import streamlit as st
import requests

from dashboard.data_loader import load, API


def run(context=None):
    scan_type = (context or {}).get("scan_type", "Normal")

    st.subheader("AI Analyst — CVE Explanations (Layer 3)")

    vulns = load("/vulnerabilities", scan_type)

    if vulns is None or getattr(vulns, "empty", True):
        st.info("No vulnerabilities available to analyze")
        return

    vulns.columns = [c.lower() for c in vulns.columns]

    if "cve" not in vulns.columns:
        st.warning("No CVE column found in vulnerability data")
        return

    cve_list = sorted(vulns["cve"].dropna().unique().tolist())
    selected_cve = st.selectbox("Select CVE to analyze", cve_list)

    if not selected_cve:
        return

    row = vulns[vulns["cve"] == selected_cve].iloc[0]

    st.markdown(f"**Selected CVE:** `{selected_cve}`")

    cvss_vector = row.get("cvss_vector", "")
    severity = row.get("severity", "")
    cvss_score = row.get("cvss", row.get("cvss_score", None))

    affected_assets = []
    if "host" in vulns.columns:
        affected_assets = (
            vulns[vulns["cve"] == selected_cve]["host"]
            .astype(str)
            .unique()
            .tolist()
        )

    payload = {
        "cve_id": selected_cve,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cvss_score": cvss_score,
        "affected_assets": affected_assets,
    }

    if st.button("Generate AI Explanation"):
        with st.spinner("Contacting AI engine..."):
            try:
                r = requests.post(
                    f"{API}/layer3/cve/summary", json=payload, timeout=60
                )
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                st.error(f"Error calling AI endpoint: {e}")
                return

        st.markdown("### Simple Summary")
        st.write(data.get("simple_summary", ""))

        st.markdown("### Simple Description")
        st.write(data.get("simple_description", ""))

        st.markdown("### Affected Products")
        products = data.get("affected_products", [])
        st.write(", ".join(products) if products else "Not detected")

        st.markdown("### Suggested Fixes")
        for fix in data.get("fixes", []):
            st.markdown(f"- {fix}")

        st.markdown("### EPSS‑style Score")
        st.write(
            f"Current: {data.get('epss_score')} | "
            f"30‑day: {data.get('epss_30d_prediction')}"
        )

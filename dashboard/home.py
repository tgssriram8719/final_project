import streamlit as st

from dashboard.data_loader import load_scan_metadata, load


def run(context=None):
    scan_type = (context or {}).get("scan_type", "Normal")

    meta = load_scan_metadata(scan_type)

    st.header("Overview")
    st.markdown(
        f"**Scan Type:** `{meta.get('scan_type', scan_type)}` "
        f"**Target:** `{meta.get('target', 'N/A')}`"
    )

    nmap_df = load("/nmap/results", scan_type)
    vuln_df = load("/vulnerabilities", scan_type)

    c1, c2, c3 = st.columns(3)

    total_hosts = (
        int(nmap_df["host"].nunique())
        if not nmap_df.empty and "host" in nmap_df.columns
        else 0
    )

    total_vulns = len(vuln_df) if not vuln_df.empty else 0

    critical = (
        int(
            vuln_df["severity"].astype(str).str.upper().eq("CRITICAL").sum()
        )
        if not vuln_df.empty and "severity" in vuln_df.columns
        else 0
    )

    c1.metric("Hosts Scanned", total_hosts)
    c2.metric("Total Vulnerabilities", total_vulns)
    c3.metric("Critical Vulns", critical)

    st.markdown("---")
    st.markdown(
        "Use the tabs above to dive into Nmap, vulnerabilities, risk, and AI analysis."
    )

import streamlit as st
import plotly.express as px
import pandas as pd

from dashboard.data_loader import load


def run(context=None):
    scan_type = (context or {}).get("scan_type", "Normal")

    st.subheader("Nmap — Scan Results & Insights")

    df = load("/nmap/results", scan_type)

    # optional: show first rows to verify wiring
    # st.write(df.head())

    if df is None or len(df) == 0:
        st.info("No Nmap scan results available")
        return

    df.columns = [c.lower() for c in df.columns]

    total_hosts = int(df["host"].nunique()) if "host" in df.columns else len(df)
    unique_services = int(df["service"].nunique()) if "service" in df.columns else 0

    open_ports = 0
    if "state" in df.columns:
        try:
            open_ports = int(
                (df["state"].astype(str).str.lower() == "open").sum()
            )
        except Exception:
            open_ports = 0

    k1, k2, k3 = st.columns(3)
    k1.metric("Total Hosts", total_hosts)
    k2.metric("Open Ports", open_ports)
    k3.metric("Unique Services", unique_services)

    st.markdown("---")

    plotly_template = st.session_state.get("plotly_template", "plotly_dark")

    if "service" in df.columns and not df.empty:
        svc = df["service"].astype(str).value_counts().head(10)
        fig = px.bar(
            svc.reset_index().rename(
                columns={"index": "service", "service": "count"}
            ),
            x="service",
            y="count",
            title="Top Services Found",
            template=plotly_template,
        )
        st.plotly_chart(fig, use_container_width=True)

    if "port" in df.columns:
        try:
            ports = pd.to_numeric(df["port"], errors="coerce").dropna()
            if not ports.empty:
                fig_p = px.histogram(
                    ports,
                    x=ports,
                    nbins=40,
                    title="Port Distribution",
                    template=plotly_template,
                )
                st.plotly_chart(fig_p, use_container_width=True)
        except Exception:
            pass

    st.markdown("---")
    st.markdown("**Nmap Raw Results**")
    st.dataframe(df, use_container_width=True)

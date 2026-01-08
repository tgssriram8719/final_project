import streamlit as st
import requests
import pandas as pd

API = "http://localhost:8000"


def auth_headers():
    token = st.session_state.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


@st.cache_data(show_spinner=False)
def load(endpoint: str, scan_type: str = "Normal") -> pd.DataFrame:
    """
    Generic loader for list/dict endpoints from the backend.
    """
    try:
        r = requests.get(
            API + endpoint,
            params={"scan_type": scan_type},
            headers=auth_headers(),
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()

        if isinstance(data, list):
            return pd.DataFrame(data)
        return pd.DataFrame([data])
    except Exception as e:
        st.error(f"API error: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=60)
def load_scan_metadata(scan_type: str = "Normal") -> dict:
    """
    Fetch metadata for last scan (type, target, etc.).
    """
    try:
        r = requests.get(
            API + "/scan/metadata",
            params={"scan_type": scan_type},
            headers=auth_headers(),
            timeout=5,
        )
        return r.json()
    except Exception:
        return {"scan_type": scan_type}

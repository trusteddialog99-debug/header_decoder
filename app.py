import re
import tempfile
import os
from io import BytesIO

import streamlit as st
import pandas as pd
import extract_msg
from email.utils import parseaddr

st.set_page_config(page_title="MSG Header Analyzer (Enhanced)", layout="wide")

st.title("MSG Header Analyzer – Erweiterte Version")
st.markdown(
    """
    Lade `.msg`- oder `.eml`-Dateien hoch — die App extrahiert:
    - **DKIM Domain (d=)**
    - **DKIM Selector (s=)**
    - **From-Domain**
    - **Return-Path-Domain**
    - automatische Erkennung, ob vollständige Header vorhanden sind

    Unterstützt: **MSG + EML**
    """
)

uploaded_files = st.file_uploader(
    "Dateien hochladen (.msg oder .eml)", type=["msg", "eml"], accept_multiple_files=True
)

def extract_from_eml(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except:
        text = raw.decode("latin1", errors="ignore")
    return text.split("\n\n", 1)[0]

def extract_from_msg(path: str) -> str | None:
    try:
        m = extract_msg.Message(path)
    except:
        return None

    candidates = []

    for attr in ("header", "headers", "get_headers", "get_header"):
        if hasattr(m, attr):
            v = getattr(m, attr)
            try:
                h = v() if callable(v) else v
                if isinstance(h, dict):
                    h = "\n".join(f"{k}: {v}" for k, v in h.items())
                if isinstance(h, bytes):
                    h = h.decode("latin1","ignore")
                if isinstance(h, str) and h.strip():
                    candidates.append(h)
            except:
                pass

    if candidates:
        return candidates[0]

    try:
        with open(path,"rb") as f:
            raw = f.read()
        decoded = raw.decode("latin1","ignore")
        parts = decoded.split("\n\n",1)
        return parts[0]
    except:
        return None

def parse_headers(headers_text: str) -> dict:
    res = {
        "dkim_domain": "",
        "dkim_selector": "",
        "from_domain": "",
        "returnpath_domain": "",
        "header_present": "yes" if headers_text else "no"
    }

    # DKIM
    dkim_match = re.search(r"(?mi)^dkim-signature:\s*((?:[^\r\n]|\r?\n[ \t])+)", headers_text)
    if dkim_match:
        dkim = dkim_match.group(1)
        d_match = re.search(r"\bd=([^;\s]+)", dkim)
        s_match = re.search(r"\bs=([^;\s]+)", dkim)
        if d_match:
            res["dkim_domain"] = d_match.group(1)
        if s_match:
            res["dkim_selector"] = s_match.group(1)

    # From
    fm = re.search(r"(?mi)^from:\s*(.*)", headers_text)
    if fm:
        _, addr = parseaddr(fm.group(1))
        if "@" in addr:
            res["from_domain"] = addr.split("@",1)[1]

    # Return-Path
    rp = re.search(r"(?mi)^return-path:\s*(.*)", headers_text)
    if rp:
        _, addr = parseaddr(rp.group(1))
        if "@" in addr:
            res["returnpath_domain"] = addr.split("@",1)[1]

    return res

results = []

if uploaded_files:
    for up in uploaded_files:
        if up.name.lower().endswith(".eml"):
            headers = extract_from_eml(up.read())
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
                tmp.write(up.read())
                path = tmp.name
            headers = extract_from_msg(path)
            os.remove(path)

        parsed = parse_headers(headers or "")

        results.append({
            "filename": up.name,
            **parsed
        })

    df = pd.DataFrame(results)
    st.dataframe(df)

    st.download_button(
        "CSV herunterladen",
        df.to_csv(index=False).encode("utf-8"),
        "header_analysis.csv",
        "text/csv"
    )
else:
    st.info("Bitte Dateien hochladen…")

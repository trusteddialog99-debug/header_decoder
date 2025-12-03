import streamlit as st
import pandas as pd
import extract_msg
import tempfile
import os
import re
from email.utils import parseaddr


st.set_page_config(page_title="MSG/EML Header Analyzer", layout="wide")

st.title("MSG / EML Header Analyzer – korrigierte Version")
st.markdown("""
Extrahiert zuverlässig:
- DKIM Domain (d=)
- DKIM Selector (s=)
- From-Domain
- Return-Path-Domain  
Unterstützt vollständig: **.msg + .eml**
""")


# -----------------------------------------------------------
# EML HEADER EXTRACTOR
# -----------------------------------------------------------
def extract_from_eml(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except:
        text = raw.decode("latin1", errors="ignore")

    return text.split("\n\n", 1)[0]


# -----------------------------------------------------------
# MSG HEADER EXTRACTOR (KORRIGIERT!)
# -----------------------------------------------------------
def extract_from_msg(path: str) -> str | None:
    try:
        msg = extract_msg.Message(path)
    except:
        return None

    # Outlook stores INTERNET HEADERS in PR_TRANSPORT_MESSAGE_HEADERS:
    #   __substg1.0_007D001F  (Unicode)
    #   __substg1.0_007D001E  (ASCII)
    headers = None

    # Try Unicode header property
    if hasattr(msg, "properties") and "007D001F" in msg.properties:
        headers = msg.properties["007D001F"].value

    # Try ASCII header property
    if not headers and "007D001E" in msg.properties:
        headers = msg.properties["007D001E"].value

    # Ensure string
    if isinstance(headers, bytes):
        try:
            headers = headers.decode("utf-8", errors="ignore")
        except:
            headers = headers.decode("latin1", errors="ignore")

    return headers


# -----------------------------------------------------------
# HEADER PARSER
# -----------------------------------------------------------
def parse_headers(headers: str) -> dict:
    result = {
        "dkim_domain": "",
        "dkim_selector": "",
        "from_domain": "",
        "returnpath_domain": "",
        "headers_found": "yes" if headers else "no"
    }

    if not headers:
        return result

    # DKIM
    dkim = re.search(r"(?mi)^dkim-signature:\s*((?:[^\r\n]|[\r\n][ \t])+)", headers)
    if dkim:
        block = dkim.group(1)
        d = re.search(r"\bd=([^;]+)", block)
        s = re.search(r"\bs=([^;]+)", block)
        if d: result["dkim_domain"] = d.group(1).strip()
        if s: result["dkim_selector"] = s.group(1).strip()

    # From
    fm = re.search(r"(?mi)^from:\s*(.*)", headers)
    if fm:
        _, addr = parsead_

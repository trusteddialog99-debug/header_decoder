import streamlit as st
import extract_msg
import re
import pandas as pd

# Funktion zum Extrahieren der Header-Informationen
def extract_email_headers(msg_file):
    msg = extract_msg.Message(msg_file)
    headers = msg.header

    # DKIM-Domain
    dkim_domain = None
    dkim_selector = None
    return_path_domain = None

    # DKIM-Signature analysieren
    dkim_match = re.search(r'd=(\S+);', headers)
    selector_match = re.search(r's=(\S+);', headers)
    if dkim_match:
        dkim_domain = dkim_match.group(1)
    if selector_match:
        dkim_selector = selector_match.group(1)

    # From-Domain
    from_match = re.search(r'From:\s.*@([^\s>]+)', headers)
    from_domain = from_match.group(1) if from_match else None

    # Return-Path-Domain
    return_match = re.search(r'Return-Path:\s<.*@([^\s>]+)>', headers)
    if return_match:
        return_path_domain = return_match.group(1)

    return {
        "DKIM-Domain": dkim_domain,
        "DKIM-Selector": dkim_selector,
        "From-Domain": from_domain,
        "Return-Path-Domain": return_path_domain
    }

# Streamlit UI
st.title("Email Header Analyzer")
st.write("Lade eine oder mehrere .msg-Dateien hoch, um DKIM- und Domain-Informationen zu extrahieren.")

uploaded_files = st.file_uploader("Wähle .msg-Dateien", type=["msg"], accept_multiple_files=True)

if uploaded_files:
    data = []
    for file in uploaded_files:
        headers_info = extract_email_headers(file)
        headers_info["Datei"] = file.name
        data.append(headers_info)

    df = pd.DataFrame(data)
    st.write("### Extrahierte Header-Informationen")
    st.dataframe(df)

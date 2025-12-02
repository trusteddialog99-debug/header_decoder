
def extract_email_headers(msg_file):
    msg = extract_msg.Message(msg_file)

    # Header als String zusammenbauen
    if msg.header:
        headers = msg.header
    elif msg.headerDict:
        headers = "\n".join([f"{k}: {v}" for k, v in msg.headerDict.items()])
    else:
        headers = ""

    # DKIM-Domain und Selector
    dkim_domain = None
    dkim_selector = None
    return_path_domain = None

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

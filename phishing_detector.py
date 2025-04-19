import re

def detect_phishing_indicators(email_data):
    indicators = []
    score = 0

    from_email = email_data.get('From', '')
    to_email = email_data.get('To', '')
    subject = email_data.get('Subject', '')
    return_path = email_data.get('Return-Path', '')
    body = email_data.get('Body', '')  # Assume body is part of email_data, if available
    received = email_data.get('Received', [])

    # 1. Mismatched display name & email
    match = re.search(r"(.*)<(.*)>", from_email)
    if match:
        name_part = match.group(1).strip().lower()
        email_part = match.group(2).strip().lower()
        email_username = email_part.split('@')[0]
        if name_part and name_part not in email_username:
            indicators.append("⚠️ Mismatched display name and email.")
            score += 2

    # 2. Suspicious keywords in subject
    suspicious_keywords = ["password", "urgent", "verify", "account locked", "click here", "confirm", "free", "limited time offer"]
    for keyword in suspicious_keywords:
        if keyword in subject.lower():
            indicators.append(f"⚠️ Suspicious keyword found: '{keyword}'")
            score += 1

    # 3. Mismatched 'From' domain and 'Return-Path'
    if return_path and '@' in return_path and '@' in from_email:
        from_domain = from_email.split('@')[-1].strip('>').lower()
        return_domain = return_path.split('@')[-1].strip('>').lower()
        if from_domain != return_domain:
            indicators.append("⚠️ Domain mismatch between 'From' and 'Return-Path'")
            score += 2

    # 4. Suspicious Links in Body (URL Check)
    if body:
        urls = re.findall(r'(https?://\S+)', body)
        for url in urls:
            # Check for URL shortening services
            if "bit.ly" in url or "goo.gl" in url:
                indicators.append(f"⚠️ Suspicious shortened URL found: {url}")
                score += 2
            # Check if URL domain matches the sender's domain
            if not url.startswith(f"http://{from_domain}") and not url.startswith(f"https://{from_domain}"):
                indicators.append(f"⚠️ URL in body doesn't match the sender's domain: {url}")
                score += 3

    # 5. Unusual Attachments (Check for common malicious extensions)
    # Assuming you extract attachments info as well, here's a simple placeholder:
    attachments = email_data.get('Attachments', [])
    malicious_extensions = [".exe", ".vbs", ".scr", ".xls", ".docm", ".zip"]
    for attachment in attachments:
        if any(attachment.lower().endswith(ext) for ext in malicious_extensions):
            indicators.append(f"⚠️ Malicious attachment detected: {attachment}")
            score += 3

    # 6. IP Geolocation Check (optional: based on received headers and extracted IPs)
    for line in received:
        # Example: Extract IPs from 'Received' headers
        ip_match = re.search(r'\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]', line)
        if ip_match:
            ip = ip_match.group(1)
            # Example logic: If IP is from a country with known spam sources, flag it
            # You could replace this with an actual geolocation API call.
            suspicious_ips = ['203.0.113.0', '198.51.100.0']  # Example list of suspicious IPs
            if ip in suspicious_ips:
                indicators.append(f"⚠️ Suspicious IP found: {ip}")
                score += 2

    # 7. Check for missing standard email headers (DKIM, SPF, etc.)
    if 'DKIM' not in email_data or 'SPF' not in email_data:
        indicators.append("⚠️ Missing important headers (DKIM, SPF)")
        score += 3

    return indicators, score

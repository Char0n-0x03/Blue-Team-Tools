import re
from email import policy
from email.parser import BytesParser
import sys

def parse_email_body(msg):
    """Extract plain text body from email."""
    parts = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
                    except:
                        parts.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            parts.append(payload.decode(msg.get_content_charset() or "utf-8", errors="replace"))

    return "\n".join(parts)


# === IOC REGEX PATTERNS ===
IOC_PATTERNS = {
    "domain": r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|co|uk|info|top|io|ru|cn|biz|xyz)\b",
    "url": r"https?://[^\s]+",
}

def extract_iocs(text):
    """Extract IOCs from plain text using regex patterns."""
    results = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text)
        results[ioc_type] = list(set(matches))
    return results

# -----------------------------
# Extract Attachments
# -----------------------------
def extract_attachments(msg):
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
    return attachments

# -----------------------------
# Parse Email Headers
# -----------------------------
def parse_email_headers(msg):
    headers = {}

    headers["date"] = msg.get("Date")
    headers["from"] = msg.get("From")
    headers["subject"] = msg.get("Subject")
    headers["to"] = msg.get("To")
    headers["message_id"] = msg.get("Message-ID")
    headers["return_path"] = msg.get("Return-Path")

    headers["authentication_results"] = msg.get("Authentication-Results")
    headers["spf"] = msg.get("Received-SPF")
    headers["dkim"] = msg.get("DKIM-Signature")
    headers["dmarc"] = msg.get("DMARC-Filter")

    # Extract source IP from Received headers
    received_headers = msg.get_all("Received", [])
    source_ip = None
    for rh in received_headers:
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", rh)
        if match:
            source_ip = match.group(0)
            break

    headers["source_ip"] = source_ip

    return headers

# -----------------------------
# Write Output to File
# -----------------------------
def write_output_to_file(metadata, body_text):
    filename = "email-output.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("**Headers:**\n")
        for key, value in metadata.items():
            f.write(f"{key}: {value if value else 'None'}\n")

        f.write("\n**EmailBody:** ===\n")
        f.write(body_text + "\n")

    print(f"\nOutput saved to {filename}")

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python eioc.py <filename>")
        sys.exit(1)

    email_file = sys.argv[1]
    with open(email_file, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    metadata = parse_email_headers(msg)

    # Add attachments
    attachments = extract_attachments(msg)
    metadata["attachments"] = ", ".join(attachments) if attachments else "None"

    # Extract body + IOCs
    email_parsed = parse_email_body(msg)
    iocs = extract_iocs(email_parsed)
    metadata["urls"] = ", ".join(iocs["url"]) if iocs["url"] else "None"
    metadata["domains"] = ", ".join(iocs["domain"]) if iocs["domain"] else "None"

    # Write everything to file
    write_output_to_file(metadata, email_parsed)

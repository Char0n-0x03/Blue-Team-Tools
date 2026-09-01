📌 Overview

This project is a Python-based Email Forensic Parser designed for security analysts, incident responders, and threat hunters.
It extracts key forensic metadata, attachments, and Indicators of Compromise (IOCs) from .eml email files.
The tool supports:
Email header parsing
Authentication results (SPF, DKIM, DMARC)
Source IP extraction
Attachment name extraction
IOC extraction (URLs, domains)
Clean aligned output for easy reading
CLI usage (python eioc.py <email-file.eml>)

🚀 Features

The parser extracts:
Date
From
To
Subject
Message-ID
Return-Path
Authentication-Results
SPF
DKIM
DMARC
Source IP (from Received headers)

📎 Attachment Extraction

Lists all attachment filenames found in the email.

🕵️ IOC Extraction

Extracts:
URLs
Domains
Regex patterns can be extended easily.

▶️ Usage

Run the script with an .eml file:

```python eioc.py <email-file.eml>```

Example:

```python eioc.py sample.eml```

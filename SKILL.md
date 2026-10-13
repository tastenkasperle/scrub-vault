---
name: scrub-vault
description: >
  Zero-data-leak PII masking and privacy airgap for AI agents. Intercepts confidential data
  (emails, IBANs, IP addresses, credit cards, SSNs, API keys) in local RAM, replaces them with
  deterministic tokens before sending to Cloud LLMs, and seamlessly restores original values in responses.
metadata:
  author: Christopher (Diamantenschmiede)
  license: Apache-2.0
  homepage: https://github.com/tastenkasperle/scrub-vault
  pypi: https://pypi.org/project/scrub-vault/
  pricing: free
  tags:
    - privacy
    - security
    - mcp
    - gdpr
    - pii-masking
    - zero-leak
---

# 🛡️ ScrubVault: AI Agent Privacy Airgap & PII Masking

You have access to **ScrubVault**, an ultra-fast, zero-dependency in-memory privacy proxy and Model Context Protocol (MCP) engine.

## 🎯 When to Use This Skill

Activate and apply ScrubVault when:
1. **Confidential Customer / User Data:** Working with database dumps, log files, user records, invoices, or customer support transcripts containing personal data.
2. **GDPR / Privacy Compliance:** When processing data under strict European GDPR / HIPAA requirements that prohibit unencrypted PII transmission to third-party AI APIs.
3. **Sensitive Secrets & Tokens:** Redacting IP addresses, server credentials, or secrets before consulting cloud intelligence.

---

## ⚙️ Installation & Prerequisites

ScrubVault is a pure-Python package with **zero third-party dependencies**.

```bash
pip install scrub-vault
```

To run as a Model Context Protocol (MCP) server:

```bash
python -m scrub_vault.mcp
```

Or add to your MCP client configuration (`claude_desktop_config.json`, Cursor, Antigravity, or Cline):

```json
{
  "mcpServers": {
    "scrub-vault": {
      "command": "python",
      "args": ["-m", "scrub_vault.mcp"]
    }
  }
}
```

---

## 🛠️ Core Agent Workflow

Whenever handling raw text or logs containing confidential data:

### 1. In-Memory Masking (Before Cloud LLM Call)
ScrubVault detects and replaces sensitive entities in local RAM with deterministic tokens:

* **Email:** `john.doe@enterprise.com` ➔ `{{EMAIL_1}}`
* **IBAN / Bank Account:** `DE89 3704 0044 0532 0130 00` ➔ `{{IBAN_1}}`
* **Credit Card:** `4532 0150 1234 5678` ➔ `{{CREDIT_CARD_1}}`
* **IP Address:** `192.168.1.100` ➔ `{{IP_1}}`
* **Phone Number:** `+49 170 1234567` ➔ `{{PHONE_1}}`
* **Tax ID / SSN:** `123-45-6789` ➔ `{{SSN_1}}`

### 2. Forward Cleaned Prompt
Send only the masked prompt (containing `{{EMAIL_1}}` etc.) to the external LLM. **Zero PII leaves the local machine.**

### 3. Restoring PII (After LLM Responds)
When the LLM returns its analysis or code containing the tokens, ScrubVault's unmasking function restores the original values instantly in local memory for the end user.

---

## 💻 Python Code Pattern (For Tools & Subagents)

```python
from scrub_vault import ScrubVault

vault = ScrubVault()

# Step 1: Mask locally in RAM
raw_text = "Please invoice client max.mustermann@firma.de with IBAN DE89370400440532013000."
masked_prompt, session_id = vault.mask(raw_text)
# masked_prompt: "Please invoice client {{EMAIL_1}} with IBAN {{IBAN_1}}."

# Step 2: Send masked_prompt safely to Cloud LLM
llm_reply = call_cloud_llm(masked_prompt)
# llm_reply: "Invoice prepared for {{EMAIL_1}} to account {{IBAN_1}}."

# Step 3: Unmask the reply deterministically
final_result = vault.unmask(llm_reply, session_id)
# final_result: "Invoice prepared for max.mustermann@firma.de to account DE89370400440532013000."
```

---

## 🔒 Security Guarantees
- **Local In-Memory Only:** No mappings are written to disk, database, or external telemetry.
- **Deterministic Tokenization:** The same entity in a conversation maintains the exact same token throughout the context.
- **Zero-Vulnerability Audited:** Tested under Raptor Guard SAST with 0 dependencies.

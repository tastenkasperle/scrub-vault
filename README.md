# 🛡️ ScrubVault: Zero-Data-Leak AI Airgap & Reversible PII Masking Engine

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Python)-brightgreen.svg)]()
[![Raptor Guard Certified](https://img.shields.io/badge/SAST%20Audit-0%20Vulnerabilities-success.svg)]()
[![GDPR Art. 32](https://img.shields.io/badge/Compliance-GDPR%20Art.%2032%20Airgap-orange.svg)]()

> **Send sensitive data to Cloud LLMs (ChatGPT, Claude, Gemini) without ever leaking confidential PII.**

ScrubVault is a lightweight, zero-dependency in-memory privacy proxy and Model Context Protocol (MCP) server. It intercept prompts, replaces personal identifiable information (emails, IBANs, IP addresses, credit cards, tax IDs) with deterministic local tokens (`{{EMAIL_1}}`, `{{IBAN_1}}`), and restores the original values when the AI responds.

---

## 🚀 The Architecture

```
                   +----------------------------------+
                   |  Your Prompt (Confidential PII)  |
                   +----------------------------------+
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │    ScrubVault (Local RAM)   │
                      │  - Scans & Masks Sensitive  │
                      │  - Stores Mapping in Memory │
                      └─────────────────────────────┘
                                     │
                                     ▼ (Masked Prompt: "{{EMAIL_1}}, {{IBAN_1}}")
                      ┌─────────────────────────────┐
                      │    Public Cloud LLM API     │
                      │   (OpenAI / Anthropic / ...) │
                      │   *Zero PII is transmitted* │
                      └─────────────────────────────┘
                                     │
                                     ▼ (Response with tokens)
                      ┌─────────────────────────────┐
                      │    ScrubVault (Local RAM)   │
                      │  - Deterministic Unmasking  │
                      └─────────────────────────────┘
                                     │
                                     ▼
                   +----------------------------------+
                   |  End-User Result (Restored PII)  |
                   +----------------------------------+
```

---

## ⚡ Quickstart

### 1. Python SDK (Zero Dependencies)

```python
from src.core.vault import ScrubVault

vault = ScrubVault()

# 1. Mask sensitive input
input_text = "Order for client Max, email: max@corp.de, IBAN: DE89370400440532013000"
result = vault.mask(input_text)

print(result.masked_text)
# Output: "Order for client Max, email: {{EMAIL_1}}, IBAN: {{IBAN_1}}"

# 2. Transmit result.masked_text to your LLM of choice...
ai_response = "Received confirmation for {{EMAIL_1}} on account {{IBAN_1}}."

# 3. Unmask locally
clean_response = vault.unmask(ai_response, result.token_map)
print(clean_response)
# Output: "Received confirmation for max@corp.de on account DE89370400440532013000."
```

### 2. Standalone CLI

```bash
# Calculate GDPR Art. 32 Risk Score
python -m src.cli.main audit "Contract with Herr Schmidt, IBAN: DE89370400440532013000"

# Mask a dataset file directly
python -m src.cli.main scrub-dataset input.json output_clean.json
```

---

## 🤖 Model Context Protocol (MCP) Integration

ScrubVault includes a native stdio Model Context Protocol (MCP) server. Add it to your `claude_desktop_config.json` or Antigravity configuration:

```json
{
  "mcpServers": {
    "scrub_vault": {
      "command": "python",
      "args": ["-m", "src.mcp.server"],
      "cwd": "/path/to/scrub_vault"
    }
  }
}
```

### Available MCP Tools:
* `scrub_mask_text`: Masks PII in input text and returns a reversible token map.
* `scrub_unmask_text`: Replaces tokens with original values.
* `scrub_audit_risk`: Calculates risk scores and detection breakdowns.
* `scrub_anonymize_json`: Recursively scrubs JSON structures.

---

## 🛡️ Security & Clean Code Standard

* **Pure Python Standard Library:** Zero third-party dependencies (`re`, `json`, `sys`, `typing`).
* **In-Memory Vault:** Token maps live exclusively in volatile RAM and are never written to disk.
* **ReDoS Hardened:** Regex patterns are strictly bounded against algorithmic complexity attacks.
* **Audit Passed:** Tested and verified by Raptor Guard SAST (0 Critical, 0 High, 0 Medium findings).

---

## 📄 License
Apache License 2.0. Open-source research and engineering by the **Diamantenschmiede**.

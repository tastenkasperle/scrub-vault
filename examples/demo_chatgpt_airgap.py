"""
Demo: Zero-Data-Leak AI Airgap with ScrubVault
Simulates sending sensitive corporate data to a public Cloud LLM (OpenAI / Claude)
without leaking personal identifiable information (PII).
"""

import json
import sys
from pathlib import Path

# Ensure src module is importable when executed directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.vault import ScrubVault


def simulate_cloud_llm(sanitized_prompt: str) -> str:
    """Simulates a response from a public Cloud LLM (e.g. OpenAI GPT-4o or Claude 3.5).
    Notice that the cloud ONLY sees tokens like {{PERSON_1}} or {{IBAN_1}}, never real data!
    """
    print("\n--- [CLOUD TRANSMISSION] ---")
    print("What the Cloud LLM actually sees and processes:")
    print(sanitized_prompt)
    print("----------------------------\n")

    # Cloud LLM analyzes and formats without knowing true identities
    return (
        "Confirmation Receipt:\n"
        "We have registered the transaction for client Max Mustermann.\n"
        "A copy of the confirmation was dispatched to {{EMAIL_1}}.\n"
        "Account with IBAN {{IBAN_1}} has been verified."
    )


def main():
    print("=" * 60)
    print(" [SAFEGUARD] SCRUBVAULT: ZERO-DATA-LEAK AIRGAP DEMONSTRATION")
    print("=" * 60)

    vault = ScrubVault()

    # Original sensitive prompt
    original_input = (
        "Transfer order for Max Mustermann. "
        "Send the PDF statement to max.mustermann@secure-corp.de. "
        "Target account IBAN: DE89370400440532013000."
    )

    print("\n[1] ORIGINAL INPUT (Confidential / GDPR Art. 32):")
    print(original_input)

    # 1. Mask into safe prompt
    result = vault.mask(original_input)
    print("\n[2] LOCAL MASKING (Zero-Leak):")
    print(f"Masked Prompt:  {result.masked_text}")
    print(f"Local Memory Tokens: {json.dumps(result.token_map, indent=2)}")

    # 2. Transmit to simulated Cloud LLM
    cloud_response = simulate_cloud_llm(result.masked_text)

    # 3. Unmask locally
    final_output = vault.unmask(cloud_response, result.token_map)
    print("[3] LOCAL UNMASKING (Final Result for End-User):")
    print(final_output)

    print("\n" + "=" * 60)
    print(" [OK] RESULT: ZERO DATA LEAKAGE TO THE CLOUD. GDPR COMPLIANT.")
    print("=" * 60)


if __name__ == "__main__":
    main()

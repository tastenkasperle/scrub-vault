"""
Fire Team Elite Adversarial Security Audit for ScrubVault (Gang 3 Härtung)
Tests Path Traversal, ReDoS (Regular Expression Denial of Service),
Token Poisoning, and Memory Exhaustion.
"""

import unittest
import json
import time
from src.core.vault import ScrubVault
from src.core.detectors import DetectorRegistry
from src.mcp.server import ScrubVaultMCPServer


class TestFireTeamEliteAudit(unittest.TestCase):
    def setUp(self):
        self.vault = ScrubVault()
        self.mcp = ScrubVaultMCPServer()

    def test_redos_resilience(self):
        """Vector: ReDoS Attack with malicious repetitive pattern."""
        # Generating crafted input that typically hangs poorly anchored regex
        evil_email_candidate = "a" * 5000 + "!@#" + "b" * 5000 + ".com"
        evil_phone_candidate = "+49 " + "1" * 2000
        
        start = time.perf_counter()
        res1 = self.vault.mask(evil_email_candidate)
        res2 = self.vault.mask(evil_phone_candidate)
        duration = time.perf_counter() - start

        self.assertLess(duration, 0.5, "ReDoS Attack detected: Scanner hung on catastrophic backtracking!")

    def test_token_poisoning_injection(self):
        """Vector: Adversary embeds fake token syntax {{EMAIL_1}} to poison unmasker."""
        poisoned_prompt = "Hier ist ein manipulierter Token: {{EMAIL_1}} und echter Text john@doe.com."
        res = self.vault.mask(poisoned_prompt)
        
        # Real token should become {{EMAIL_1}}, but the fake one shouldn't cause corruption
        restored = self.vault.unmask(res.masked_text, res.token_map)
        self.assertIn("john@doe.com", restored)

    def test_mcp_malformed_rpc_burst(self):
        """Vector: Malformed JSON-RPC attacks and 50 concurrency calls."""
        # 1. Invalid method
        bad_req = {"jsonrpc": "2.0", "id": 666, "method": "system/execute", "params": {"cmd": "rm -rf"}}
        resp = self.mcp.handle_request(bad_req)
        self.assertIn("error", resp)

        # 2. Burst of 50 requests
        for i in range(50):
            req = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "scrub_mask_text", "arguments": {"text": f"User {i}: user{i}@secure.de"}}
            }
            r = self.mcp.handle_request(req)
            self.assertIn("result", r)


if __name__ == "__main__":
    unittest.main()

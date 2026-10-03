"""
Comprehensive Unit & Integration Tests for ScrubVault
Tests Core Detectors, Reversible Vault, Dataset Scrubber, and MCP Protocol.
Anti-Carbonara: 100% Hermetic, In-Memory.
"""

import unittest
import json
from src.core.detectors import DetectorRegistry, EmailDetector, PhoneDetector, IBANCardDetector
from src.core.vault import ScrubVault
from src.core.dataset import DatasetScrubber
from src.mcp.server import ScrubVaultMCPServer


class TestScrubVault(unittest.TestCase):
    def setUp(self):
        self.vault = ScrubVault()
        self.dataset_scrubber = DatasetScrubber(self.vault)
        self.mcp_server = ScrubVaultMCPServer()

    def test_email_and_phone_detection(self):
        sample = "Kontaktieren Sie Max Mustermann unter max.mustermann@example.com oder mobil +49 170 1234567."
        res = self.vault.mask(sample)
        
        self.assertIn("{{EMAIL_1}}", res.masked_text)
        self.assertIn("{{PHONE_1}}", res.masked_text)
        self.assertNotIn("max.mustermann@example.com", res.masked_text)
        self.assertEqual(res.token_map["{{EMAIL_1}}"], "max.mustermann@example.com")

        # Test reversible unmasking
        restored = self.vault.unmask(res.masked_text, res.token_map)
        self.assertEqual(restored, sample)

    def test_iban_and_ip_detection(self):
        sample = "Server IP: 192.168.1.50, Bankkonto: DE89370400440532013000."
        res = self.vault.mask(sample)
        
        self.assertIn("{{IP_ADDRESS_1}}", res.masked_text)
        self.assertIn("{{IBAN_1}}", res.masked_text)
        
        restored = self.vault.unmask(res.masked_text, res.token_map)
        self.assertEqual(restored, sample)

    def test_consistent_token_mapping(self):
        # The same email appearing twice must receive the EXACT same token
        sample = "Schreiben an john@corp.com. Nochmals john@corp.com bestätigen."
        res = self.vault.mask(sample)
        
        self.assertEqual(res.masked_text.count("{{EMAIL_1}}"), 2)
        self.assertNotIn("{{EMAIL_2}}", res.masked_text)

    def test_audit_risk_scoring(self):
        safe_text = "Dies ist ein unbedenklicher Text ohne persönliche Daten."
        safe_res = self.vault.audit_risk(safe_text)
        self.assertEqual(safe_res["risk_score"], 0)
        self.assertEqual(safe_res["risk_level"], "LOW")
        self.assertTrue(safe_res["compliant_with_cloud_llm"])

        critical_text = "IBAN: DE89370400440532013000, IP: 10.0.0.1, Mail: test@bank.de"
        crit_res = self.vault.audit_risk(critical_text)
        self.assertGreaterEqual(crit_res["risk_score"], 30)
        self.assertFalse(crit_res["compliant_with_cloud_llm"])

    def test_json_dataset_scrubbing(self):
        payload = {
            "user": {
                "name": "Erika",
                "email": "erika.muster@firma.de",
                "ip": "172.16.0.4"
            },
            "logs": ["Fehler bei Anfrage von erika.muster@firma.de"]
        }
        res = self.dataset_scrubber.scrub_json(payload)
        scrubbed = res["scrubbed_data"]
        
        self.assertIn("{{EMAIL_1}}", scrubbed["user"]["email"])
        self.assertIn("{{IP_ADDRESS_1}}", scrubbed["user"]["ip"])
        self.assertIn("{{EMAIL_1}}", scrubbed["logs"][0])

    def test_mcp_server_protocol(self):
        # 0. initialize & ping
        init_req = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}
        init_resp = self.mcp_server.handle_request(init_req)
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "scrub-vault")
        self.assertIn("tools", init_resp["result"]["capabilities"])

        # Notification should return None
        notify_req = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.assertIsNone(self.mcp_server.handle_request(notify_req))

        # Ping
        ping_resp = self.mcp_server.handle_request({"jsonrpc": "2.0", "id": "p1", "method": "ping"})
        self.assertEqual(ping_resp["result"], {})

        # 1. tools/list
        list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        list_resp = self.mcp_server.handle_request(list_req)
        tools = [t["name"] for t in list_resp["result"]["tools"]]
        self.assertIn("scrub_mask_text", tools)
        self.assertIn("scrub_unmask_text", tools)

        # 2. tools/call scrub_mask_text
        mask_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "scrub_mask_text",
                "arguments": {"text": "Mail: ceo@startup.io"}
            }
        }
        mask_resp = self.mcp_server.handle_request(mask_req)
        content = json.loads(mask_resp["result"]["content"][0]["text"])
        self.assertIn("{{EMAIL_1}}", content["masked_text"])
        token_map = content["token_map"]

        # 3. tools/call scrub_unmask_text
        unmask_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scrub_unmask_text",
                "arguments": {
                    "text": "Antwort an {{EMAIL_1}} gesendet.",
                    "token_map": token_map
                }
            }
        }
        unmask_resp = self.mcp_server.handle_request(unmask_req)
        self.assertEqual(unmask_resp["result"]["content"][0]["text"], "Antwort an ceo@startup.io gesendet.")


if __name__ == "__main__":
    unittest.main()

"""
ScrubVault MCP Server: Stdio-basierter JSON-RPC 2.0 Server für KI-Agenten.
Anti-Carbonara Standard: Pure Core Integration.
"""

import sys
import json
import logging
from src.core.vault import ScrubVault
from src.core.dataset import DatasetScrubber

# Set logging to stderr to prevent interference with stdout JSON-RPC
logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(message)s")


class ScrubVaultMCPServer:
    def __init__(self):
        self.vault = ScrubVault()
        self.dataset_scrubber = DatasetScrubber(self.vault)
        self.tools = [
            {
                "name": "scrub_mask_text",
                "description": "Masks sensitive PII (emails, phones, IBANs, IPs, tax IDs) from text and generates a local token_map for zero-leakage prompt forwarding.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "The input text to mask"}
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "scrub_unmask_text",
                "description": "Restores original sensitive values into an LLM response using the local token_map.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "The LLM response containing masked tokens like {{EMAIL_1}}"},
                        "token_map": {"type": "object", "description": "The token map dictionary returned during masking"}
                    },
                    "required": ["text", "token_map"]
                }
            },
            {
                "name": "scrub_audit_risk",
                "description": "Audits a text or document for GDPR / DSGVO Art. 32 PII risks and returns an audit score.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to analyze for privacy compliance"}
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "scrub_anonymize_json",
                "description": "Recursively scans and anonymizes all PII in a JSON data structure for safe staging or testing.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "data": {"type": "object", "description": "JSON object or dictionary"}
                    },
                    "required": ["data"]
                }
            }
        ]

    def handle_request(self, req: dict) -> dict:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "scrub-vault",
                        "version": "1.0.0"
                    }
                }
            }

        elif method == "notifications/initialized":
            return None

        elif method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {}
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.tools}
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})

            try:
                if tool_name == "scrub_mask_text":
                    res = self.vault.mask(args.get("text", ""))
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "masked_text": res.masked_text,
                                    "token_map": res.token_map,
                                    "findings_count": res.findings_count,
                                    "summary": res.findings_summary
                                }, indent=2)
                            }]
                        }
                    }

                elif tool_name == "scrub_unmask_text":
                    res_text = self.vault.unmask(args.get("text", ""), args.get("token_map", {}))
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": res_text
                            }]
                        }
                    }

                elif tool_name == "scrub_audit_risk":
                    audit = self.vault.audit_risk(args.get("text", ""))
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": json.dumps(audit, indent=2)
                            }]
                        }
                    }

                elif tool_name == "scrub_anonymize_json":
                    res = self.dataset_scrubber.scrub_json(args.get("data", {}))
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": json.dumps(res, indent=2)
                            }]
                        }
                    }

                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Method {tool_name} not found"}
                    }

            except Exception as e:
                logging.exception(f"Error executing tool {tool_name}")
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": str(e)}
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid Request"}
        }

    def run(self):
        logging.info("ScrubVault MCP Server started on stdio.")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                logging.exception("Failed to process stdio line")


if __name__ == "__main__":
    server = ScrubVaultMCPServer()
    server.run()

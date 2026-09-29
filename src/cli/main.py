"""
ScrubVault CLI: Dünner Argument-Parser.
Anti-Carbonara: Delegiert 100% der Logik an src.core.vault.
"""

import sys
import os
import json
import argparse
from src.core.vault import ScrubVault
from src.core.dataset import DatasetScrubber


def main() -> int:
    parser = argparse.ArgumentParser(description="ScrubVault: DSGVO Airgap & Reversible PII Masking")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: mask
    mask_parser = subparsers.add_parser("mask", help="Mask text or file and export token map")
    mask_parser.add_argument("input", help="Text string or path to text file")
    mask_parser.add_argument("--map-out", help="Optional path to save token_map.json", default=None)

    # Command: unmask
    unmask_parser = subparsers.add_parser("unmask", help="Restore original data using token map")
    unmask_parser.add_argument("input", help="Masked text or path to file")
    unmask_parser.add_argument("--map", required=True, help="Path to token_map.json")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Check DSGVO Art. 32 risk of text or file")
    audit_parser.add_argument("input", help="Text string or path to file")

    args = parser.parse_args()
    vault = ScrubVault()

    def get_text(val: str) -> str:
        if os.path.isfile(val):
            with open(val, "r", encoding="utf-8") as f:
                return f.read()
        return val

    if args.command == "mask":
        text = get_text(args.input)
        res = vault.mask(text)
        if args.map_out:
            with open(args.map_out, "w", encoding="utf-8") as f:
                json.dump(res.token_map, f, indent=2)
        print(res.masked_text)
        return 0

    elif args.command == "unmask":
        text = get_text(args.input)
        with open(args.map, "r", encoding="utf-8") as f:
            token_map = json.load(f)
        restored = vault.unmask(text, token_map)
        print(restored)
        return 0

    elif args.command == "audit":
        text = get_text(args.input)
        audit_res = vault.audit_risk(text)
        print(json.dumps(audit_res, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

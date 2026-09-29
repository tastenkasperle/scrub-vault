"""
ScrubVault Core: Dataset & Structured Anonymizer
Handles CSV and JSON data structures with consistent anonymization.
Pure Python, Zero External Dependencies.
"""

import json
import csv
import io
from typing import Dict, Any, List, Union
from src.core.vault import ScrubVault


class DatasetScrubber:
    def __init__(self, vault: ScrubVault = None):
        self.vault = vault or ScrubVault()

    def scrub_json(self, data: Union[str, Dict, List]) -> Dict[str, Any]:
        """Deep scrubs all string values in a JSON structure."""
        if isinstance(data, str):
            parsed = json.loads(data)
        else:
            parsed = data

        token_map_all: Dict[str, str] = {}
        total_modified = 0

        def _traverse(node):
            nonlocal total_modified
            if isinstance(node, dict):
                return {k: _traverse(v) for k, v in node.items()}
            elif isinstance(node, list):
                return [_traverse(elem) for elem in node]
            elif isinstance(node, str):
                res = self.vault.mask(node)
                if res.findings_count > 0:
                    total_modified += res.findings_count
                    token_map_all.update(res.token_map)
                    return res.masked_text
                return node
            return node

        scrubbed = _traverse(parsed)
        return {
            "scrubbed_data": scrubbed,
            "token_map": token_map_all,
            "modified_fields": total_modified
        }

    def scrub_csv(self, csv_content: str, delimiter: str = ",") -> Dict[str, Any]:
        """Scrubs tabular CSV content while preserving header and format."""
        reader = csv.reader(io.StringIO(csv_content), delimiter=delimiter)
        rows = list(reader)
        if not rows:
            return {"scrubbed_csv": "", "token_map": {}, "rows_processed": 0}

        header = rows[0]
        scrubbed_rows = [header]
        token_map_all: Dict[str, str] = {}
        total_findings = 0

        for row in rows[1:]:
            scrubbed_row = []
            for cell in row:
                res = self.vault.mask(cell)
                if res.findings_count > 0:
                    total_findings += res.findings_count
                    token_map_all.update(res.token_map)
                    scrubbed_row.append(res.masked_text)
                else:
                    scrubbed_row.append(cell)
            scrubbed_rows.append(scrubbed_row)

        out_io = io.StringIO()
        writer = csv.writer(out_io, delimiter=delimiter, lineterminator="\n")
        writer.writerows(scrubbed_rows)

        return {
            "scrubbed_csv": out_io.getvalue(),
            "token_map": token_map_all,
            "rows_processed": len(rows) - 1,
            "total_findings": total_findings
        }

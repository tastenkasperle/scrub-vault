"""
ScrubVault Core: Reversible Vault Engine
Handles masking, placeholder mapping, and deterministic unmasking.
Pure Python, Zero External Dependencies.
"""

from typing import Dict, Any, List, NamedTuple
from src.core.detectors import DetectorRegistry, Finding


class MaskResult(NamedTuple):
    masked_text: str
    token_map: Dict[str, str]
    findings_count: int
    findings_summary: Dict[str, int]


class ScrubVault:
    def __init__(self, registry: DetectorRegistry = None):
        self.registry = registry or DetectorRegistry()

    def mask(self, text: str) -> MaskResult:
        findings = self.registry.scan(text)
        token_map: Dict[str, str] = {}
        type_counters: Dict[str, int] = {}
        summary: Dict[str, int] = {}

        # First pass: map each unique value to a consistent token
        val_to_token: Dict[str, str] = {}
        for f in findings:
            if f.value not in val_to_token:
                current_count = type_counters.get(f.entity_type, 0) + 1
                type_counters[f.entity_type] = current_count
                token = f"{{{{{f.entity_type}_{current_count}}}}}"
                val_to_token[f.value] = token
                token_map[token] = f.value
            
            summary[f.entity_type] = summary.get(f.entity_type, 0) + 1

        # Second pass: construct masked text from end to start to maintain indices
        masked_chars = list(text)
        for f in reversed(findings):
            token = val_to_token[f.value]
            masked_chars[f.start:f.end] = list(token)

        masked_text = "".join(masked_chars)

        return MaskResult(
            masked_text=masked_text,
            token_map=token_map,
            findings_count=len(findings),
            findings_summary=summary
        )

    def unmask(self, text: str, token_map: Dict[str, str]) -> str:
        """Restores original values by replacing tokens from token_map."""
        result = text
        # Replace tokens (order by length descending to prevent substring collisions)
        sorted_tokens = sorted(token_map.keys(), key=len, reverse=True)
        for token in sorted_tokens:
            original_val = token_map[token]
            result = result.replace(token, original_val)
        return result

    def audit_risk(self, text: str) -> Dict[str, Any]:
        """Calculates DSGVO Art. 32 Risk Score and breakdown."""
        findings = self.registry.scan(text)
        summary: Dict[str, int] = {}
        high_risk_types = {"CREDIT_CARD", "IBAN", "SSN", "TAX_ID"}
        risk_score = 0

        for f in findings:
            summary[f.entity_type] = summary.get(f.entity_type, 0) + 1
            if f.entity_type in high_risk_types:
                risk_score += 25
            else:
                risk_score += 10

        risk_score = min(100, risk_score)
        level = "LOW"
        if risk_score >= 60:
            level = "CRITICAL"
        elif risk_score >= 30:
            level = "MEDIUM"

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "total_findings": len(findings),
            "breakdown": summary,
            "compliant_with_cloud_llm": risk_score == 0
        }

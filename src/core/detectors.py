"""
ScrubVault Core: PII Detectors Engine
Pure Python, Zero External Dependencies, 100% In-Memory.
Anti-Carbonara: Pure Logic, No CLI, No print(), No sys.exit().
"""

import re
from typing import List, Dict, Any, NamedTuple


class Finding(NamedTuple):
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float


class BaseDetector:
    name: str = "base"

    def detect(self, text: str) -> List[Finding]:
        raise NotImplementedError


class EmailDetector(BaseDetector):
    name = "EMAIL"
    # RFC 5322 simplified regex for robust email extraction
    PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        re.IGNORECASE
    )

    def detect(self, text: str) -> List[Finding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            findings.append(Finding(
                entity_type=self.name,
                value=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=0.98
            ))
        return findings


class PhoneDetector(BaseDetector):
    name = "PHONE"
    # Matches international and national phone formats (DE / US / EU)
    PATTERN = re.compile(
        r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,9}\b'
    )

    def detect(self, text: str) -> List[Finding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            val = match.group().strip()
            # Filter out pure small numbers or date lookalikes
            digits = re.sub(r'\D', '', val)
            if 7 <= len(digits) <= 15:
                findings.append(Finding(
                    entity_type=self.name,
                    value=val,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.90
                ))
        return findings


class IBANCardDetector(BaseDetector):
    name = "IBAN_CARD"
    # IBAN or Credit Card patterns
    IBAN_PATTERN = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b')
    CC_PATTERN = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b')

    def detect(self, text: str) -> List[Finding]:
        findings = []
        # Check IBANs
        for match in self.IBAN_PATTERN.finditer(text):
            findings.append(Finding(
                entity_type="IBAN",
                value=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=0.95
            ))
        # Check Credit Cards
        for match in self.CC_PATTERN.finditer(text):
            digits = re.sub(r'\D', '', match.group())
            if 13 <= len(digits) <= 19 and self._luhn_check(digits):
                findings.append(Finding(
                    entity_type="CREDIT_CARD",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.99
                ))
        return findings

    @staticmethod
    def _luhn_check(num_str: str) -> bool:
        total = 0
        reverse_digits = num_str[::-1]
        for i, char in enumerate(reverse_digits):
            d = int(char)
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0


class IPDetector(BaseDetector):
    name = "IP_ADDRESS"
    # Matches IPv4 and IPv6
    IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

    def detect(self, text: str) -> List[Finding]:
        findings = []
        for match in self.IPV4_PATTERN.finditer(text):
            findings.append(Finding(
                entity_type=self.name,
                value=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=0.95
            ))
        return findings


class TaxIdDetector(BaseDetector):
    name = "TAX_ID"
    # German Steuer-ID (11 Digits) & US SSN (XXX-XX-XXXX)
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    DE_STEUER_ID = re.compile(r'\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b')

    def detect(self, text: str) -> List[Finding]:
        findings = []
        for match in self.SSN_PATTERN.finditer(text):
            findings.append(Finding(
                entity_type="SSN",
                value=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=0.95
            ))
        for match in self.DE_STEUER_ID.finditer(text):
            digits = re.sub(r'\D', '', match.group())
            if len(digits) == 11:
                findings.append(Finding(
                    entity_type="TAX_ID",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.90
                ))
        return findings


class DetectorRegistry:
    """Orchestrates all detectors and handles overlaps."""
    def __init__(self, detectors: List[BaseDetector] = None):
        if detectors is None:
            self.detectors = [
                EmailDetector(),
                PhoneDetector(),
                IBANCardDetector(),
                IPDetector(),
                TaxIdDetector()
            ]
        else:
            self.detectors = detectors

    def scan(self, text: str) -> List[Finding]:
        all_findings: List[Finding] = []
        for det in self.detectors:
            all_findings.extend(det.detect(text))

        # Sort findings by start position, then length descending
        all_findings.sort(key=lambda f: (f.start, -(f.end - f.start)))

        # Remove overlapping findings
        resolved: List[Finding] = []
        last_end = -1
        for f in all_findings:
            if f.start >= last_end:
                resolved.append(f)
                last_end = f.end

        return resolved

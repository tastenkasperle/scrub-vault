# SPEC: ScrubVault (DSGVO Airgap & Reversible PII Masking Engine)
**Status:** In Schmiede (Gang 1 - Architektur & Spezifikation)  
**Standard:** Anti-Carbonara Pure Clean Code & AYA-Protokoll

---

## 1. Vision & Core Value Proposition
ScrubVault ist eine leichtgewichtige, hochperformante, 100% lokale Zero-Leakage PII-Maskierungs- und Anonymisierungs-Engine.
- **Problem:** Unternehmen, Kanzleien und Entwickler leaken sensible Daten (PII) an Cloud-LLMs (ChatGPT, Claude, Gemini) oder verstoßen gegen DSGVO Art. 32 bei Staging-Datenbanken.
- **Lösung:** Reversibles Maskieren im RAM vor dem Prompten (`token_map`) + Zero-Leakage Rückübersetzung nach der LLM-Antwort. Plus: Direkte Anonymisierung von JSON-, CSV- und SQL-Datensätzen mit synthetischen Daten.
- **Anti-Carbonara Doktrin:**
  - `src/core/`: Reine Geschäftslogik, 0 CLI-Imports, 0 `print()`, 0 `sys.exit()`. Gibt strukturierte DTOs/Ergebnisse zurück.
  - `src/cli/`: Dünner Argument-Parser, formatiert Ausgaben via stdout/stderr, setzt Exit-Codes.
  - `src/mcp/`: Nativer JSON-RPC 2.0 MCP-Server für KI-Agenten und IDEs.
  - `tests/`: Autarke Unittests & Fuzzing-Tests.

---

## 2. Architektur & Komponenten

### 2.1 `src/core/detectors.py`
Detektoren zur Identifizierung von PII ("Filth"):
- Email (RFC 5322 Regex)
- Telefonnummern (DE/International/Mobil)
- IBAN / Kreditkartennummern (Luhn-Validierung)
- IP-Adressen (IPv4 / IPv6)
- Personenbezogene Namen & Identifikatoren (Heuristik / Dictionary / Kontext)
- Steuernummern / Steuer-ID / SSN

### 2.2 `src/core/vault.py`
Die reversible Masking-Engine (`Vault`):
- `mask(text: str) -> MaskResult`:
  - Ersetzt Treffer durch konsistente anonyme Platzhalter: `{{PERSON_1}}`, `{{EMAIL_1}}`, `{{IBAN_1}}`.
  - Liefert `masked_text`, Liste der `findings` und eine verschlüsselte/im RAM gehaltene `token_map`.
- `unmask(text: str, token_map: dict) -> str`:
  - Setzt die Originalwerte wieder präzise an die Stelle der Platzhalter ein.

### 2.3 `src/core/dataset.py`
Staging- & Dataset-Anonymisierer:
- Anonymisiert JSON-Objekte/Arrays.
- Anonymisiert CSV-Tabellen (Spaltenweise konfigurierbar).
- Anonymisiert SQL INSERT / VALUES Statements unter Beibehaltung der referentiellen Integrität.

### 2.4 `src/cli/main.py`
Befehle:
- `scrubvault mask <file-or-text>`
- `scrubvault unmask <file-or-text> --map <token_map.json>`
- `scrubvault anonymize-csv <input.csv> <output.csv>`
- `scrubvault audit <file>` (DSGVO-Risikobewertung)

### 2.5 `src/mcp/server.py`
Exponierte MCP-Tools:
- `scrub_mask_text`: Maskiert Text, liefert maskedText und tokenMap zurück.
- `scrub_unmask_text`: Übersetzt LLM-Antwort mittels tokenMap zurück.
- `scrub_anonymize_json`: Anonymisiert komplexe JSON-Strukturen.
- `scrub_audit_risk`: Scannt Text/Datensatz auf PII-Gefahren für DSGVO Art. 32 Audit.

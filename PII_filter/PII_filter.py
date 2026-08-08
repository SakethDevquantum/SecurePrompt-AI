import re
import json
import logging
import math
from typing import List, Dict, Any, Optional
import requests

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.predefined_recognizers import EmailRecognizer, PhoneRecognizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurePromptPIIFilter")

try:
    analyzer = AnalyzerEngine()
except Exception as e:
    logger.warning(f"Could not load full Presidio Analyzer Engine (usually due to missing spacy model): {e}")
    analyzer = None

# loads en_core_web_sm spacy model under the hood of AnalyzerEngine()

api_key_pattern = Pattern(
    name="api_key",
    regex=r"(?i)\b(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?",
    score=0.95
)

sk_key_pattern = Pattern(
    name="sk_key",
    regex=r"\bsk-[a-zA-Z0-9-]{12,}\b",
    score=0.95
)

cloud_aq_pattern = Pattern(
    name="cloud_aq_token",
    regex=r"\bAQ\.[a-zA-Z0-9._\-]{15,}\b",
    score=0.98
)

jwt_pattern = Pattern(
    name="jwt_token",
    regex=r"eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-__]+",
    score=0.95
)

internal_url_pattern = Pattern(
    name="internal_url",
    regex=r"(https?://)?[a-zA-Z0-9-_.]+\.corp(/\S*)?",
    score=0.90
)

date_pattern = Pattern(
    name="date_pattern",
    regex=r"\b\d{4}[-/]\d{2}[-/]\d{2}\b",
    score=0.85
)

address_pattern = Pattern(
    name="street_address",
    regex=r"\b\d{1,5}\s+[A-Za-z0-9\s#.,-]+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Way|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Circle|Cir)\b(?:,\s*[A-Za-z0-9\s]+)*(?:\s+[A-Z]{2})?(?:\s+\d{5})?",
    score=0.85
)

cvv_pattern = Pattern(
    name="cvv",
    regex=r"(?i)\b(?:cvv|cvc|security\s*code|cid)\s*[:=-]?\s*(\d{3,4})\b",
    score=0.95
)

aadhaar_pattern = Pattern(
    name="aadhaar",
    regex=r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    score=0.95
)

pan_pattern = Pattern(
    name="pan_number",
    regex=r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b",
    score=0.95
)

death_threat_pattern = Pattern(
    name="death_threat",
    regex=r"(?i)\b(?:I will kill you|you will die for this|I'm going to kill you|I will end your life|You are going to die)\b",
    score=0.99
)

blood_group_pattern = Pattern(name="blood_group", regex=r"(?i)\b(A|B|AB|O)[+-]\b", score=0.95)
upi_pattern = Pattern(name="upi_id", regex=r"(?i)\b[a-zA-Z0-9.\-_]{2,256}@(upi|okaxis|okicici|oksbi|okhdfcbank|ybl|ibl|axl|paytm|apl|axisbank|icici|hdfcbank|sbi|kotak|yesbank)\b", score=0.95)
passport_pattern = Pattern(name="passport", regex=r"\b[A-Z]{1}[0-9]{7}\b", score=0.95)
bank_account_pattern = Pattern(name="bank_account", regex=r"\b\d{10,18}\b", score=0.85)
ssn_pattern = Pattern(name="ssn", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=0.95)
ip_pattern = Pattern(name="ip_address", regex=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", score=0.95)
mac_pattern = Pattern(name="mac_address", regex=r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", score=0.95)
crypto_pattern = Pattern(name="crypto_wallet", regex=r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", score=0.95)
vehicle_plate_pattern = Pattern(name="vehicle_plate", regex=r"\b[A-Z]{2}[- ]?\d{2}[- ]?[A-Z]{1,2}[- ]?\d{4}\b", score=0.85)


if analyzer:
    api_key_recognizer = PatternRecognizer(
        supported_entity="CREDENTIALS",
        patterns=[api_key_pattern, sk_key_pattern, cloud_aq_pattern]
    )
    analyzer.registry.add_recognizer(api_key_recognizer)

    jwt_recognizer = PatternRecognizer(
        supported_entity="JWT",
        patterns=[jwt_pattern]
    )
    analyzer.registry.add_recognizer(jwt_recognizer)

    url_recognizer = PatternRecognizer(
        supported_entity="INTERNAL_URL",
        patterns=[internal_url_pattern]
    )
    analyzer.registry.add_recognizer(url_recognizer)

    date_recognizer = PatternRecognizer(
        supported_entity="DATE_TIME",
        patterns=[date_pattern]
    )
    analyzer.registry.add_recognizer(date_recognizer)

    address_recognizer = PatternRecognizer(
        supported_entity="ADDRESS",
        patterns=[address_pattern]
    )
    analyzer.registry.add_recognizer(address_recognizer)
    
    cvv_recognizer = PatternRecognizer(
        supported_entity="CREDIT_CARD_CVV",
        patterns=[cvv_pattern]
    )
    analyzer.registry.add_recognizer(cvv_recognizer)
    
    aadhaar_recognizer = PatternRecognizer(
        supported_entity="AADHAAR_NUMBER",
        patterns=[aadhaar_pattern]
    )
    analyzer.registry.add_recognizer(aadhaar_recognizer)
    
    pan_recognizer = PatternRecognizer(
        supported_entity="PAN_NUMBER",
        patterns=[pan_pattern]
    )
    analyzer.registry.add_recognizer(pan_recognizer)

    threat_recognizer = PatternRecognizer(
        supported_entity="THREAT",
        patterns=[death_threat_pattern]
    )
    analyzer.registry.add_recognizer(threat_recognizer)

    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="BLOOD_GROUP", patterns=[blood_group_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="UPI_ID", patterns=[upi_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="PASSPORT", patterns=[passport_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="US_BANK_NUMBER", patterns=[bank_account_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="SSN", patterns=[ssn_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="IP_ADDRESS", patterns=[ip_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="MAC_ADDRESS", patterns=[mac_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="CRYPTO_WALLET", patterns=[crypto_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="VEHICLE_PLATE", patterns=[vehicle_plate_pattern]))

    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="BLOOD_GROUP", patterns=[blood_group_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="UPI_ID", patterns=[upi_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="PASSPORT", patterns=[passport_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="US_BANK_NUMBER", patterns=[bank_account_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="SSN", patterns=[ssn_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="IP_ADDRESS", patterns=[ip_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="MAC_ADDRESS", patterns=[mac_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="CRYPTO_WALLET", patterns=[crypto_pattern]))
    analyzer.registry.add_recognizer(PatternRecognizer(supported_entity="VEHICLE_PLATE", patterns=[vehicle_plate_pattern]))

    enterprise_keywords = [
        "Apollo", "Project Apollo", "Saketh", "SecurePrompt", "SentinelPrompt"
    ]
    enterprise_recognizer = PatternRecognizer(
        supported_entity="CLIENT_PROJECT_DATA",
        deny_list=enterprise_keywords
    )
    analyzer.registry.add_recognizer(enterprise_recognizer)

def detect_all_tokens_and_keys(text: str) -> List[Dict[str, Any]]:
    tokens = []
    
    prefix_pattern = r"(?i)\b(?:api[_\s-]?key|secret|token|bearer|auth|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?"
    for m in re.finditer(prefix_pattern, text):
        matched_val = m.group(1)
        full_match = m.group(0)
        tokens.append({"item": matched_val, "type": "CREDENTIALS", "severity": "High", "confidence": 0.95})
        tokens.append({"item": full_match, "type": "CREDENTIALS", "severity": "High", "confidence": 0.95})

    # Passwords (allowing special chars like !@#$%^&*)
    password_pattern = r"(?i)\b(?:password|passwd)\s*[:=]\s*(\S+)"
    for m in re.finditer(password_pattern, text):
        tokens.append({"item": m.group(1), "type": "PASSWORD", "severity": "High", "confidence": 0.95})
        tokens.append({"item": m.group(0), "type": "PASSWORD", "severity": "High", "confidence": 0.95})

    # Usernames
    username_pattern = r"(?i)\b(?:username|user(?:[\s_-]?id)?|login)\s*[:=]\s*([a-zA-Z0-9._@-]{3,})"
    for m in re.finditer(username_pattern, text):
        tokens.append({"item": m.group(1), "type": "USERNAME", "severity": "Medium", "confidence": 0.95})
        tokens.append({"item": m.group(0), "type": "USERNAME", "severity": "Medium", "confidence": 0.95})

    # Security Questions
    sec_q_pattern = r"(?i)\b(?:security\s*question)\s*[:=]\s*(.*?)(?=\n|$)"
    for m in re.finditer(sec_q_pattern, text):
        tokens.append({"item": m.group(0).strip(), "type": "SECURITY_QUESTION", "severity": "Medium", "confidence": 0.95})

    # Security Answers
    sec_a_pattern = r"(?i)\b(?:security\s*answer|answer)\s*[:=]\s*(.*?)(?=\n|$)"
    for m in re.finditer(sec_a_pattern, text):
        tokens.append({"item": m.group(0).strip(), "type": "SECURITY_ANSWER", "severity": "High", "confidence": 0.95})

    # Recovery Codes / OTPs
    otp_pattern = r"(?i)\b(?:recovery\s*code|otp|one\s*time\s*password|2fa\s*code|backup\s*code)\s*[:=]\s*([A-Za-z0-9-]+)"
    for m in re.finditer(otp_pattern, text):
        tokens.append({"item": m.group(1), "type": "OTP", "severity": "High", "confidence": 0.95})
        tokens.append({"item": m.group(0), "type": "OTP", "severity": "High", "confidence": 0.95})

    cloud_patterns = [
        r"\bsk-[a-zA-Z0-9._\-]{10,}\b",
        r"\bhf_[a-zA-Z0-9]{20,}\b",
        r"\bAIzaSy[a-zA-Z0-9._\-]{33}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bAQ\.[a-zA-Z0-9._\-]{15,}\b",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b",
        r"\bgithub_pat_[a-zA-Z0-9_]{80,}\b",
        r"\bxox[baprs]-[a-zA-Z0-9-]{10,}\b",
        r"eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-__]+",
        r"\b[a-zA-Z0-9/+=]{40}\b"
    ]
    for cp in cloud_patterns:
        for m in re.finditer(cp, text):
            tokens.append({"item": m.group(0), "type": "CREDENTIALS", "severity": "High", "confidence": 0.98})

    words = re.findall(r"\b[a-zA-Z0-9._\-/+=]{20,}\b", text)
    for word in words:
        if word.startswith("http://") or word.startswith("https://") or word.isdigit() or len(word) < 20:
            continue
        has_upper = any(c.isupper() for c in word)
        has_lower = any(c.islower() for c in word)
        has_num = any(c.isdigit() for c in word)
        has_spec = any(c in "._-/+=" for c in word)
        
        prob = [float(word.count(c)) / len(word) for c in set(word)]
        entropy = -sum([p * math.log2(p) for p in prob])
        
        if (has_upper and has_lower and (has_num or has_spec)) and entropy >= 3.4:
            tokens.append({"item": word, "type": "CREDENTIALS", "severity": "High", "confidence": 0.95})

    return tokens

def fallback_regex_scanner(text: str) -> List[Dict[str, Any]]:
    entities = []

    email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    phone_regex = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    api_key_regex = r"\b(?:sk-[a-zA-Z0-9-]{12,}|AIzaSy[a-zA-Z0-9._\-]{33}|AKIA[0-9A-Z]{16})\b"

    cvv_regex = r"(?i)\b(?:cvv|cvc|security\s*code|cid)\s*[:=-]?\s*(\d{3,4})\b"
    aadhaar_regex = r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
    pan_regex = r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b"
    threat_regex = r"(?i)\b(?:I will kill you|you will die for this|I'm going to kill you|I will end your life|You are going to die)\b"

    for match in re.finditer(email_regex, text):
        entities.append({"item": match.group(), "type": "EMAIL_ADDRESS", "severity": "High", "confidence": 0.99})

    for match in re.finditer(phone_regex, text):
        entities.append({"item": match.group(), "type": "PHONE_NUMBER", "severity": "Medium", "confidence": 0.85})

    for match in re.finditer(api_key_regex, text):
        entities.append({"item": match.group(), "type": "CREDENTIALS", "severity": "High", "confidence": 0.99})
        
    for match in re.finditer(cvv_regex, text):
        entities.append({"item": match.group(), "type": "CREDIT_CARD_CVV", "severity": "High", "confidence": 0.95})
        
    for match in re.finditer(aadhaar_regex, text):
        entities.append({"item": match.group(), "type": "AADHAAR_NUMBER", "severity": "High", "confidence": 0.95})
        
    for match in re.finditer(pan_regex, text):
        entities.append({"item": match.group(), "type": "PAN_NUMBER", "severity": "High", "confidence": 0.95})

    for match in re.finditer(threat_regex, text):
        entities.append({"item": match.group(), "type": "THREAT", "severity": "High", "confidence": 0.99})

    return entities


def perform_pii_analysis(prompt_text: str) -> Dict[str, Any]:
    """Scans prompt text for PII/Secrets and calculates calibrated risk score."""
    # Pre-clean the text to remove already redacted tags and explicit "Redacted" mentions
    # This prevents the scanner from hallucinating on safe files or prompts containing "Redacted xyz"
    safe_text = re.sub(r'(?i)\[?REDACTED_[A-Z0-9_]+\]?', '', prompt_text)
    safe_text = re.sub(r'(?i)redacted\s+[a-z]+', '', safe_text)
    
    # Exclude exact mock templates to prevent recursive flagging
    mock_templates = [
        "examplepassword@temp", "example_username", "john_doe@example.com", "+91 123-456-8273",
        "01/01/0001", "123 example street, Secureville, CA 90210", "john doe", "ak_live_xYz123MockKey987",
        "1234-5678-9012", "ABCDE1234F", "123", "1111-2222-3333-4444", "oab+-", "example_name_or_no@bank_id",
        "A1234567", "0000111122223333", "000-00-0000", "192.168.0.1", "00:00:00:00:00:00", 
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "MH-01-AB-1234"
    ]
    for mock in mock_templates:
        safe_text = safe_text.replace(mock, "")
    
    findings = []
    
    findings.extend(detect_all_tokens_and_keys(safe_text))
    
    if analyzer:
        try:
            results = analyzer.analyze(text=safe_text, language="en")
            for res in results:
                matched_item = safe_text[res.start:res.end]
                entity_type = res.entity_type
                severity = "Medium"
                
                if entity_type in ["EMAIL_ADDRESS", "US_BANK_NUMBER", "CREDENTIALS", "JWT", "INTERNAL_URL", "CREDIT_CARD_CVV", "AADHAAR_NUMBER", "PAN_NUMBER", "THREAT"]:
                    severity = "High"
                elif entity_type in ["PHONE_NUMBER", "PERSON", "DATE_TIME"]:
                    severity = "Medium"
                else:
                    severity = "Low"
                    
                findings.append({
                    "item": matched_item,
                    "type": entity_type,
                    "severity": severity,
                    "confidence": float(res.score)
                })
        except Exception as e:
            logger.error(f"Presidio analyze error: {e}. Using fallback scanner.")
            findings.extend(fallback_regex_scanner(safe_text))
    else:
        findings.extend(fallback_regex_scanner(safe_text))
        
    filtered_findings = []
    for f in findings:
        item_lower = f["item"].lower()
        ftype = f["type"].upper()
        
        filtered_findings.append(f)

    seen = set()
    deduped_findings = []
    for f in filtered_findings:
        if f["item"] not in seen:
            seen.add(f["item"])
            deduped_findings.append(f)

    # ── CONFIGURABLE POLICY ──────────────────────────────────────────────────
    # Base severity (0-100) per entity type.
    # High values here guarantee the "critical entity floor" requirement:
    # a single Password (70) or API Key (90) can never score below its own weight.
    ENTITY_WEIGHTS = {
        # High Risk (>70)
        "CREDENTIALS":          90,
        "JWT":                  90,
        "PASSWORD":             90,
        "THREAT":               100,
        "CREDIT_CARD_CVV":      95,
        "AADHAAR_NUMBER":       95,
        "PAN_NUMBER":           95,
        "CVV":                  80,
        "CREDIT_CARD":          75,
        "SSN":                  75,
        "US_BANK_NUMBER":       75,
        "SECURITY_ANSWER":      75,
        "NRP":                  75,
        "US_DRIVER_LICENSE":    75,
        "IN_PAN":               75,
        "IN_AADHAAR":           75,
        "PHONE_NUMBER":         75,
        "IP_ADDRESS":           75,
        "FINANCIAL_DATA":       75,
        "CLIENT_PROJECT_DATA":  75,
        "BLOOD_GROUP":          75,
        "UPI_ID":               75,
        "PASSPORT":             75,
        "MAC_ADDRESS":          75,
        "CRYPTO_WALLET":        75,
        "VEHICLE_PLATE":        75,
        
        # Moderate Risk (>30)
        "OTP":                  40,
        "PERSON":               40,
        "URL":                   40,
        "INTERNAL_URL":         40,
        "EMAIL_ADDRESS":        40,
        "USERNAME":             40,
        "DATE_TIME":            40,
        "ADDRESS":              40,
        "SECURITY_QUESTION":    40,
    }

    # Combination rules: each entry is
    #   { "entities": [set of types], "multiplier": float, "label": str, "description": str }
    # The multiplier is applied to the highest individual entity weight in the combo.
    COMBINATION_RULES = [
        {
            "entities": {"CREDENTIALS", "EMAIL_ADDRESS"},
            "multiplier": 1.05,
            "label": "API Key + Email",
            "description": "Service credential with identifiable contact"
        },
        {
            "entities": {"USERNAME", "PASSWORD"},
            "multiplier": 1.15,
            "label": "Username + Password",
            "description": "Account credential exposure"
        },
        {
            "entities": {"URL", "USERNAME", "CREDENTIALS"},
            "multiplier": 1.25,
            "label": "Website + Username + Password",
            "description": "Identifiable account credential exposure"
        },
        {
            "entities": {"INTERNAL_URL", "USERNAME", "CREDENTIALS"},
            "multiplier": 1.25,
            "label": "Internal URL + Username + Password",
            "description": "Identifiable internal account credential exposure"
        },
        {
            "entities": {"SECURITY_QUESTION", "SECURITY_ANSWER"},
            "multiplier": 1.20,
            "label": "Security Question + Answer",
            "description": "Account recovery information exposure"
        },
        {
            "entities": {"USERNAME", "CREDENTIALS", "SECURITY_QUESTION", "SECURITY_ANSWER"},
            "multiplier": 1.40,
            "label": "Auth + Recovery Bundle",
            "description": "Full authentication and account recovery bundle"
        },
        {
            "entities": {"USERNAME", "PASSWORD", "SECURITY_QUESTION", "SECURITY_ANSWER"},
            "multiplier": 1.40,
            "label": "Auth + Recovery Bundle",
            "description": "Full authentication and account recovery bundle"
        },
        {
            "entities": {"CREDIT_CARD", "CVV"},
            "multiplier": 1.30,
            "label": "Credit Card + CVV",
            "description": "Payment credential bundle — card can be used for fraudulent transactions"
        },
        {
            "entities": {"US_BANK_NUMBER", "ROUTING_NUMBER"},
            "multiplier": 1.25,
            "label": "Bank Account + Routing Number",
            "description": "Banking credential bundle"
        },
        {
            "entities": {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"},
            "multiplier": 1.15,
            "label": "Name + Email + Phone",
            "description": "Identifiable personal contact bundle"
        },
        {
            "entities": {"PERSON", "DATE_TIME", "ADDRESS"},
            "multiplier": 1.20,
            "label": "Name + DOB + Address",
            "description": "Identity profile bundle"
        },
        {
            "entities": {"SSN", "PERSON"},
            "multiplier": 1.20,
            "label": "Name + SSN",
            "description": "Identity theft bundle"
        },
    ]

    # Severity thresholds (configurable)
    SEVERITY_THRESHOLDS = [
        (80, "CRITICAL RISK"),
        (60, "HIGH RISK"),
        (40, "MODERATE RISK"),
        (20, "LOW RISK"),
        (0,  "MINIMAL RISK"),
    ]

    # ── EMPTY CASE ───────────────────────────────────────────────────────────
    if not deduped_findings:
        risk_score = 0
        risk_level = "MINIMAL RISK"
        reason = "SAFE: No sensitive keys, credentials, or PII detected. Prompt is safe to transmit."
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reason": reason,
            "deduped_findings": deduped_findings
        }

    # ── STEP 1: Per-entity weights & dedup by TYPE (not item) ────────────────
    # Duplicate occurrences of the same TYPE add a small log-scale increment
    # so they're not completely ignored but also don't double-count linearly.
    # ── STEP 1: Types for grouping ───────────────────────────────────────────
    types_found = list(set(f["type"].upper() for f in deduped_findings))

    # ── STEP 2: Highest individual entity risk (critical floor) ──────────────
    individual_risks = {t: ENTITY_WEIGHTS.get(t, 5) for t in types_found}
    highest_entity_risk = max(individual_risks.values()) if individual_risks else 0

    # ── STEP 3: Noisy-OR base aggregation across all detected items ──────────
    # We iterate over EVERY matched entity (not just types) so that multiple 
    # occurrences of the same type properly compound the risk score.
    prob_safe = 1.0
    for f in deduped_findings:
        w = ENTITY_WEIGHTS.get(f["type"].upper(), 5) / 100.0
        prob_safe *= (1.0 - w)
    noisy_or_risk = 100.0 * (1.0 - prob_safe)

    # ── STEP 4: Combination detection + multiplier scoring ───────────────────
    triggered_combos = []
    best_combo_score = 0.0

    for rule in COMBINATION_RULES:
        required = rule["entities"]
        if required.issubset(set(types_found)):
            # Multiplier applied to highest individual weight among combo members
            combo_max_weight = max(
                ENTITY_WEIGHTS.get(e, 5) for e in required if e in individual_risks
            )
            combo_score = min(100.0, combo_max_weight * rule["multiplier"])
            triggered_combos.append({
                "label": rule["label"],
                "description": rule["description"],
                "score": round(combo_score, 1)
            })
            if combo_score > best_combo_score:
                best_combo_score = combo_score

    # ── STEP 5: Final score = max(floor, noisy_or, best_combo) ───────────────
    # The floor ensures a single critical entity can never be diluted.
    raw_score = max(highest_entity_risk, noisy_or_risk, best_combo_score)
    risk_score = int(round(min(100.0, raw_score)))

    # ── STEP 6: Severity level ────────────────────────────────────────────────
    risk_level = "MINIMAL RISK"
    for threshold, label in SEVERITY_THRESHOLDS:
        if risk_score >= threshold:
            risk_level = label
            break

    # ── STEP 7: Human-readable type labels ───────────────────────────────────
    # [CHALLENGE 3 SOLUTION]: Granular Entity Classification & Dynamic Human-Readable Label Mapping
    type_mapping = {
        "CREDENTIALS":       "API Keys/Secrets",
        "JWT":               "Auth Tokens",
        "CREDIT_CARD":       "Credit Card Numbers",
        "CVV":               "CVV Codes",
        "SSN":               "Social Security Numbers",
        "NRP":               "National ID Numbers",
        "IN_PAN":            "PAN Card Numbers",
        "IN_AADHAAR":        "Aadhaar Numbers",
        "OTP":               "One-Time Passwords",
        "US_BANK_NUMBER":    "Bank Account Numbers",
        "INTERNAL_URL":      "Internal URLs",
        "EMAIL_ADDRESS":     "Email Addresses",
        "FINANCIAL_DATA":    "Financial Data",
        "PHONE_NUMBER":      "Phone Numbers",
        "PERSON":            "Names",
        "DATE_TIME":         "Dates/DOB",
        "ADDRESS":           "Addresses",
        "IP_ADDRESS":        "IP Addresses",
        "URL":               "URLs",
        "US_DRIVER_LICENSE": "Driver Licenses",
        "USERNAME":          "Usernames",
        "PASSWORD":          "Passwords",
        "SECURITY_QUESTION": "Security Questions",
        "SECURITY_ANSWER":   "Security Answers",
        "CLIENT_PROJECT_DATA": "Internal Project Data",
    }
    friendly_types = sorted(
        [type_mapping.get(t, t.replace("_", " ").title()) for t in types_found]
    )
    friendly_types_str = ", ".join(friendly_types)

    # ── STEP 8: Rich explanation ──────────────────────────────────────────────
    risk_factors = []

    # Always mention the highest individual entity
    top_type = max(individual_risks, key=individual_risks.get)
    top_label = type_mapping.get(top_type, top_type.replace("_", " ").title())
    risk_factors.append(
        f"Highest single entity: {top_label} (severity {int(round(individual_risks[top_type]))})"
    )

    if len(types_found) > 1:
        risk_factors.append(f"{len(types_found)} distinct sensitive entity types detected")

    combo_labels = [c["label"] for c in triggered_combos]
    combo_descs  = [c["description"] for c in triggered_combos]

    if triggered_combos:
        for c in triggered_combos:
            risk_factors.append(f"Dangerous combination: {c['label']} — {c['description']}")

    # Build explanation sentence
    if triggered_combos:
        combo_summary = " and ".join(combo_descs)
        if risk_score >= 80:
            reason = (
                f"CRITICAL SECURITY RISK: Prompt contains {combo_summary} "
                f"({', '.join(combo_labels)}). "
                f"Detected entities: {friendly_types_str}. "
                f"Highest individual severity: {int(round(highest_entity_risk))}."
            )
        elif risk_score >= 60:
            reason = (
                f"HIGH RISK: Prompt contains {combo_summary} "
                f"({', '.join(combo_labels)}). "
                f"Detected entities: {friendly_types_str}."
            )
        else:
            reason = (
                f"MODERATE RISK: Prompt contains {combo_summary}. "
                f"Detected entities: {friendly_types_str}."
            )
    else:
        if risk_score >= 80:
            reason = (
                f"CRITICAL SECURITY RISK: Prompt exposes {top_label} "
                f"(severity {int(round(highest_entity_risk))}). "
                f"All detected: {friendly_types_str}."
            )
        elif risk_score >= 60:
            reason = (
                f"HIGH RISK: Prompt contains highly sensitive data — {friendly_types_str}. "
                f"Highest severity entity: {top_label} ({int(round(highest_entity_risk))})."
            )
        elif risk_score >= 40:
            reason = (
                f"MODERATE PRIVACY RISK: Prompt contains identifying details — {friendly_types_str}."
            )
        elif risk_score >= 20:
            reason = (
                f"LOW RISK: Minor PII detected ({friendly_types_str}). "
                f"Safe for general use but sanitize before publishing."
            )
        else:
            reason = (
                f"MINIMAL RISK: Negligible data detected ({friendly_types_str}). Safe to transmit."
            )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": reason,
        "deduped_findings": deduped_findings
    }



def perform_pii_rewrite(prompt_text: str, entities: List[Dict[str, Any]], model_name: str = "phi4-mini") -> Dict[str, str]:
    """Executes Ollama LLM prompt rewrite with mandatory fallback pass."""
    system_prompt = (
        "You are an AI Security Gateway agent. Your task is to sanitize the user's input prompt.\n"
        "Strict rules:\n"
        "1. You MUST preserve the EXACT same format, spacing, and line breaks as the original text.\n"
        "2. Replace all private entities with the following exact mock placeholders ONLY:\n"
        "   - Email -> john_doe@example.com\n"
        "   - Phone -> +91 123-456-8273\n"
        "   - Date -> 01/01/0001\n"
        "   - Address -> 123 example street, Secureville, CA 90210\n"
        "   - Name -> john doe\n"
        "   - API Key -> ak_live_xYz123MockKey987\n"
        "   - Password -> examplepassword@temp\n"
        "   - Username -> example_username\n"
        "   - Aadhaar -> 1234-5678-9012\n"
        "   - PAN -> ABCDE1234F\n"
        "   - Credit Card CVV -> 123\n"
        "   - Credit Card -> 1111-2222-3333-4444\n"
        "   - Blood Group -> oab+-\n"
        "   - UPI ID -> example_name_or_no@bank_id\n"
        "   - Passport -> A1234567\n"
        "   - Bank Account -> 0000111122223333\n"
        "   - SSN -> 000-00-0000\n"
        "   - IP Address -> 192.168.0.1\n"
        "   - MAC Address -> 00:00:00:00:00:00\n"
        "   - Crypto Wallet -> 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
        "   - Vehicle Plate -> MH-01-AB-1234\n"
        "3. Do NOT add any extra line spacings, newlines at the end, headers, or explanations.\n"
        "4. Output ONLY the exact text with placeholders substituted."
    )
    
    entities_summary = ", ".join([f"'{e.get('item','')}' (Type: {e.get('type','')})" for e in entities])
    
    user_prompt = (
        f"Original Text:\n{prompt_text}\n\n"
        f"Entities to Replace: {entities_summary}\n\n"
        f"Output EXACTLY the Original Text, but with the Entities replaced by placeholders. No extra text, spaces, or newlines."
    )

    ollama_url = "http://localhost:11434/api/generate"
    safe_prompt = prompt_text
    used_model = model_name

    try:
        response = requests.post(
            ollama_url,
            json={
                "model": model_name,
                "prompt": f"<|system|>\n{system_prompt}\n<|user|>\n{user_prompt}\n<|assistant|>\n",
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                },
                "stream": False
            },
            timeout=7.0
        )
        if response.status_code == 200:
            result = response.json()
            llm_output = result.get("response", "").strip()
            if llm_output.startswith("```") and llm_output.endswith("```"):
                lines = llm_output.split("\n")
                if len(lines) > 2:
                    llm_output = "\n".join(lines[1:-1]).strip()
            if len(llm_output) > 5:
                original_lines = len(prompt_text.split('\n'))
                llm_lines = len(llm_output.split('\n'))
                
                if llm_lines != original_lines:
                    logger.warning(f"Ollama LLM altered line spacing ({llm_lines} vs {original_lines}). Falling back to strict exact replacement.")
                    safe_prompt = prompt_text
                else:
                    if prompt_text.endswith('\n'):
                        llm_output += '\n'
                    if prompt_text.startswith('\n'):
                        llm_output = '\n' + llm_output
                    safe_prompt = llm_output
                    logger.info(f"Ollama rewrite received: {safe_prompt[:50]}...")
        else:
            used_model = "Deterministic Sanitizer Engine"
            logger.warning(f"Ollama returned status {response.status_code}. Using deterministic sanitizer.")
    except Exception as e:
        used_model = "Deterministic Sanitizer Engine"
        logger.warning(f"Ollama connection/timeout ({e}). Using deterministic sanitizer.")

    sorted_entities = sorted(entities, key=lambda x: len(x.get("item", "")), reverse=True)
    
    for ent in sorted_entities:
        item = ent.get("item", "")
        if not item or len(item.strip()) == 0:
            continue
        etype = ent.get("type", "").upper()
        
        placeholder = "ak_live_xYz123MockKey987"
        if "EMAIL" in etype:
            placeholder = "john_doe@example.com"
        elif "AADHAAR" in etype:
            placeholder = "1234-5678-9012"
        elif "PAN" in etype:
            placeholder = "ABCDE1234F"
        elif "BANK" in etype or "ROUTING" in etype:
            placeholder = "0000111122223333"
        elif "SSN" in etype or "SOCIAL" in etype:
            placeholder = "000-00-0000"
        elif "PHONE" in etype or "NUMBER" in etype:
            placeholder = "+91 123-456-8273"
        elif "DATE" in etype:
            placeholder = "01/01/0001"
        elif "ADDRESS" in etype or "LOCATION" in etype:
            placeholder = "123 example street, Secureville, CA 90210"
        elif "PERSON" in etype or "NAME" in etype:
            placeholder = "john doe"
        elif "CREDENTIAL" in etype or "KEY" in etype:
            placeholder = "ak_live_xYz123MockKey987"
        elif "PASSWORD" in etype:
            placeholder = "examplepassword@temp"
        elif "USERNAME" in etype:
            placeholder = "example_username"
        elif "CVV" in etype:
            placeholder = "123"
        elif "CREDIT_CARD" in etype or "CARD" in etype:
            placeholder = "1111-2222-3333-4444"
        elif "BLOOD" in etype:
            placeholder = "oab+-"
        elif "UPI" in etype:
            placeholder = "example_name_or_no@bank_id"
        elif "PASSPORT" in etype:
            placeholder = "A1234567"
        elif "IP_ADDRESS" in etype:
            placeholder = "192.168.0.1"
        elif "MAC" in etype:
            placeholder = "00:00:00:00:00:00"
        elif "CRYPTO" in etype or "WALLET" in etype:
            placeholder = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        elif "VEHICLE" in etype or "PLATE" in etype:
            placeholder = "MH-01-AB-1234"
        elif "THREAT" in etype:
            placeholder = "[THREAT BLOCKED]"
            
        safe_prompt = safe_prompt.replace(item, placeholder)

    safe_prompt = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "john_doe@example.com", safe_prompt)
    safe_prompt = re.sub(r"(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?", "ak_live_xYz123MockKey987", safe_prompt, flags=re.IGNORECASE)
    safe_prompt = re.sub(r"\bAQ\.[a-zA-Z0-9._\-]{15,}\b", "ak_live_xYz123MockKey987", safe_prompt)
    safe_prompt = re.sub(r"\bAIzaSy[a-zA-Z0-9._\-]{33}\b", "ak_live_xYz123MockKey987", safe_prompt)
    safe_prompt = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "ak_live_xYz123MockKey987", safe_prompt)
    safe_prompt = re.sub(r"\bsk-[a-zA-Z0-9-]{12,}\b", "ak_live_xYz123MockKey987", safe_prompt)
    safe_prompt = re.sub(r"\bhf_[a-zA-Z0-9]{20,}\b", "ak_live_xYz123MockKey987", safe_prompt)
    safe_prompt = re.sub(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "+91 123-456-8273", safe_prompt)
    safe_prompt = re.sub(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b", "01/01/0001", safe_prompt)
    
    # New specific regexes for deterministic sanitizer
    safe_prompt = re.sub(r"\b(A|B|AB|O)[+-]\b", "oab+-", safe_prompt, flags=re.IGNORECASE)
    safe_prompt = re.sub(r"\b[a-zA-Z0-9.\-_]{2,256}@(upi|okaxis|okicici|oksbi|okhdfcbank|ybl|ibl|axl|paytm|apl|axisbank|icici|hdfcbank|sbi|kotak|yesbank)\b", "example_name_or_no@bank_id", safe_prompt, flags=re.IGNORECASE)
    safe_prompt = re.sub(r"\b[A-Z]{1}[0-9]{7}\b", "A1234567", safe_prompt)
    safe_prompt = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "000-00-0000", safe_prompt)
    safe_prompt = re.sub(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "192.168.0.1", safe_prompt)
    safe_prompt = re.sub(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", "00:00:00:00:00:00", safe_prompt)
    safe_prompt = re.sub(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", safe_prompt)
    safe_prompt = re.sub(r"\b[A-Z]{2}[- ]?\d{2}[- ]?[A-Z]{1,2}[- ]?\d{4}\b", "MH-01-AB-1234", safe_prompt)
    safe_prompt = re.sub(r"\b\d{10,18}\b", "0000111122223333", safe_prompt)
    safe_prompt = re.sub(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", "ABCDE1234F", safe_prompt)
    safe_prompt = re.sub(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b", "1234-5678-9012", safe_prompt)

    return {
        "safe_prompt": safe_prompt,
        "used_model": used_model
    }

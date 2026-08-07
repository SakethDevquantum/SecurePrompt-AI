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

    for match in re.finditer(email_regex, text):
        entities.append({"item": match.group(), "type": "EMAIL_ADDRESS", "severity": "High", "confidence": 0.99})

    for match in re.finditer(phone_regex, text):
        entities.append({"item": match.group(), "type": "PHONE_NUMBER", "severity": "Medium", "confidence": 0.85})

    for match in re.finditer(api_key_regex, text):
        entities.append({"item": match.group(), "type": "CREDENTIALS", "severity": "High", "confidence": 0.99})

    return entities


def perform_pii_analysis(prompt_text: str) -> Dict[str, Any]:
    """Scans prompt text for PII/Secrets and calculates calibrated risk score."""
    findings = []
    
    findings.extend(detect_all_tokens_and_keys(prompt_text))
    
    if analyzer:
        try:
            results = analyzer.analyze(text=prompt_text, language="en")
            for res in results:
                matched_item = prompt_text[res.start:res.end]
                entity_type = res.entity_type
                severity = "Medium"
                
                if entity_type in ["EMAIL_ADDRESS", "US_BANK_NUMBER", "CREDENTIALS", "JWT", "INTERNAL_URL"]:
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
            findings.extend(fallback_regex_scanner(prompt_text))
    else:
        findings.extend(fallback_regex_scanner(prompt_text))
        
    filtered_findings = []
    for f in findings:
        item_lower = f["item"].lower()
        ftype = f["type"].upper()
        
        if ftype in ["ADDRESS", "LOCATION"] and any(x in item_lower for x in ["example", "testville", "zz"]):
            logger.info(f"Filtering out example address placeholder: {f['item']}")
            continue
            
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
        "CREDENTIALS":          90,   # API Key / Secret
        "JWT":                  90,   # Auth token
        "SSN":                  20,   # SSN / National ID
        "CREDIT_CARD":          70,
        "CVV":                  80,
        "US_BANK_NUMBER":       70,   # Bank Account
        "PASSWORD":             90,   # Explicit password entity
        "SECURITY_ANSWER":      60,
        "SECURITY_QUESTION":    40,
        "NRP":                  20,   # National Registration / ID numbers
        "US_DRIVER_LICENSE":    50,
        "IN_PAN":               20,   # India PAN card
        "IN_AADHAAR":           20,   # India Aadhaar
        "OTP":                  90,   # One-Time Passwords
        "USERNAME":             20,
        "PERSON":                5,   # Name
        "EMAIL_ADDRESS":        20,
        "PHONE_NUMBER":         15,
        "DATE_TIME":            20,   # DOB equivalent
        "ADDRESS":              20,
        "IP_ADDRESS":           10,
        "URL":                   5,
        "INTERNAL_URL":         15,
        "FINANCIAL_DATA":       25,
        "CLIENT_PROJECT_DATA":  15,
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
        "2. Replace all private entities, credentials, names, URLs, phone numbers, and dates with placeholders like [Email Address], [Phone Number], [API Key], [Name], etc.\n"
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
        
        placeholder = f"[{ent.get('type', 'Private Data')}]"
        if "EMAIL" in etype:
            placeholder = "[Email Address]"
        elif "PHONE" in etype or "NUMBER" in etype:
            if "BANK" in etype:
                placeholder = "[Bank Account Number]"
            elif "ROUTING" in etype:
                placeholder = "[Routing Number]"
            else:
                placeholder = "[Phone Number]"
        elif "DATE" in etype:
            placeholder = "[Date of Birth]"
        elif "ADDRESS" in etype or "LOCATION" in etype:
            placeholder = "[Address]"
        elif "PERSON" in etype or "NAME" in etype:
            placeholder = "[Name]"
        elif "CREDENTIAL" in etype or "KEY" in etype:
            placeholder = "[API Key]"
            
        safe_prompt = safe_prompt.replace(item, placeholder)

    safe_prompt = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[Email Address]", safe_prompt)
    safe_prompt = re.sub(r"(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?", "[API Key]", safe_prompt, flags=re.IGNORECASE)
    safe_prompt = re.sub(r"\bAQ\.[a-zA-Z0-9._\-]{15,}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bAIzaSy[a-zA-Z0-9._\-]{33}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bsk-[a-zA-Z0-9-]{12,}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bhf_[a-zA-Z0-9]{20,}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[Phone Number]", safe_prompt)
    safe_prompt = re.sub(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b", "[Date of Birth]", safe_prompt)

    return {
        "safe_prompt": safe_prompt,
        "used_model": used_model
    }

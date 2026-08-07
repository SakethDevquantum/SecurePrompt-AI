import re
import json
import logging
import math
from typing import List, Dict, Any, Optional
import requests

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.predefined_recognizers import EmailRecognizer, PhoneRecognizer

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurePromptPIIFilter")

# Initialize Presidio Analyzer Engine
try:
    analyzer = AnalyzerEngine()
except Exception as e:
    logger.warning(f"Could not load full Presidio Analyzer Engine (usually due to missing spacy model): {e}")
    analyzer = None

# loads en_core_web_sm spacy model under the hood of AnalyzerEngine()

# Custom Enterprise Recognizers & Rules
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

# Register Custom Recognizers in Presidio Engine
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


# Helper: Standalone & Multi-Delimiter Security Token Recognizer
def detect_all_tokens_and_keys(text: str) -> List[Dict[str, Any]]:
    tokens = []
    
    prefix_pattern = r"(?i)\b(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?"
    for m in re.finditer(prefix_pattern, text):
        matched_val = m.group(1)
        full_match = m.group(0)
        tokens.append({"item": matched_val, "type": "CREDENTIALS", "severity": "High", "confidence": 0.95})
        tokens.append({"item": full_match, "type": "CREDENTIALS", "severity": "High", "confidence": 0.95})

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


# Helper: Local Fallback Regex Scanner
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
        
        if ("ADDRESS" in ftype or "LOCATION" in ftype) and any(x in item_lower for x in ["example", "testville", "zz"]):
            logger.info(f"Filtering out example address placeholder: {f['item']}")
            continue
            
        filtered_findings.append(f)

    seen = set()
    deduped_findings = []
    for f in filtered_findings:
        if f["item"] not in seen:
            seen.add(f["item"])
            deduped_findings.append(f)

    if not deduped_findings:
        risk_score = 5
        risk_level = "LOW RISK"
        reason = "SAFE: No sensitive keys, credentials, or PII detected. Prompt is safe to transmit."
    else:
        category_weights = {
            "CREDENTIALS": 92,
            "JWT": 90,
            "US_BANK_NUMBER": 92,
            "CREDIT_CARD": 94,
            "SSN": 95,
            "INTERNAL_URL": 82,
            "EMAIL_ADDRESS": 78,
            "FINANCIAL_DATA": 72,
            "CLIENT_PROJECT_DATA": 60,
            "PHONE_NUMBER": 55,
            "PERSON": 50,
            "DATE_TIME": 45,
            "ADDRESS": 45,
        }

        base_weights = [category_weights.get(f["type"].upper(), 40) for f in deduped_findings]
        max_base = max(base_weights)
        
        extra_items_count = len(deduped_findings) - 1
        calculated_score = max_base + (extra_items_count * 4)
        risk_score = min(99, calculated_score)

        types_found = list(set(f["type"].upper() for f in deduped_findings))
        sample_items = [f"'{f['item'][:20]}...'" if len(f['item']) > 20 else f"'{f['item']}'" for f in deduped_findings[:3]]
        items_str = ", ".join(sample_items)

        if risk_score >= 75:
            risk_level = "HIGH RISK"
            if any(t in ["CREDENTIALS", "JWT", "CREDIT_CARD", "SSN", "US_BANK_NUMBER"] for t in types_found):
                reason = f"CRITICAL SECURITY RISK: Prompt contains exposed secret keys/credentials ({items_str}) which can grant unauthorized system access or leak sensitive tokens."
            elif "INTERNAL_URL" in types_found:
                reason = f"HIGH INFRASTRUCTURE RISK: Prompt contains internal corporate URL subdomains ({items_str}) revealing private network routes."
            else:
                reason = f"HIGH PRIVACY RISK: Prompt contains highly sensitive personal identifiers ({items_str})."
        elif risk_score >= 40:
            risk_level = "MEDIUM RISK"
            if "CLIENT_PROJECT_DATA" in types_found:
                reason = f"CONFIDENTIAL DATA RISK: Prompt contains internal project codenames or client identifiers ({items_str})."
            else:
                reason = f"MEDIUM PRIVACY RISK: Prompt contains sensitive PII details ({items_str}) such as names, phone numbers, or dates."
        else:
            risk_level = "LOW RISK"
            reason = f"LOW RISK: Minor non-critical matches detected ({items_str})."

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
                # Check if LLM added any extra line spacings or altered formatting
                original_lines = len(prompt_text.split('\n'))
                llm_lines = len(llm_output.split('\n'))
                
                if llm_lines != original_lines:
                    logger.warning(f"Ollama LLM altered line spacing ({llm_lines} vs {original_lines}). Falling back to strict exact replacement.")
                    safe_prompt = prompt_text
                else:
                    # Strictly preserve the original leading/trailing whitespaces
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

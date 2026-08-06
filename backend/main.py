import re
import json
import logging
import math
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests


from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.predefined_recognizers import EmailRecognizer, PhoneRecognizer

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurePromptBackend")

app = FastAPI(title="SecurePrompt Security & Rewrite Backend")

# Enable CORS for React frontend on port 3000
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Presidio Analyzer Engine
try:
    analyzer = AnalyzerEngine()
except Exception as e:
    logger.warning(f"Could not load full Presidio Analyzer Engine (usually due to missing spacy model): {e}")
    analyzer = None

# Custom Enterprise Recognizers & Rules
# Multi-delimiter & High-Entropy Token Recognizers

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
    # 1. API Keys & Secrets Recognizer
    api_key_recognizer = PatternRecognizer(
        supported_entity="CREDENTIALS",
        patterns=[api_key_pattern, sk_key_pattern, cloud_aq_pattern]
    )
    analyzer.registry.add_recognizer(api_key_recognizer)

    # 2. JWT Tokens Recognizer
    jwt_recognizer = PatternRecognizer(
        supported_entity="JWT",
        patterns=[jwt_pattern]
    )
    analyzer.registry.add_recognizer(jwt_recognizer)

    # 3. Internal Subdomains/URLs Recognizer
    url_recognizer = PatternRecognizer(
        supported_entity="INTERNAL_URL",
        patterns=[internal_url_pattern]
    )
    analyzer.registry.add_recognizer(url_recognizer)

    # 4. Dates Recognizer
    date_recognizer = PatternRecognizer(
        supported_entity="DATE_TIME",
        patterns=[date_pattern]
    )
    analyzer.registry.add_recognizer(date_recognizer)

    # 5. Addresses Recognizer
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


# Request/Response Schemas
class AnalyzeRequest(BaseModel):
    prompt: str

class EntityInfo(BaseModel):
    item: str
    type: str
    severity: str  # LOW, MEDIUM, HIGH
    confidence: float

class AnalyzeResponse(BaseModel):
    riskScore: int
    riskLevel: str  # LOW RISK, MEDIUM RISK, HIGH RISK
    reason: str
    entities: List[EntityInfo]

class RewriteRequest(BaseModel):
    prompt: str
    entities: List[Dict[str, Any]]
    model: Optional[str] = "phi4-mini"  # Default to phi4-mini or llama3.1

class RewriteResponse(BaseModel):
    safePrompt: str
    modelUsed: str


# Helper: Standalone & Multi-Delimiter Security Token Recognizer
def detect_all_tokens_and_keys(text: str) -> List[Dict[str, Any]]:
    tokens = []
    
    # 1. Flexible Prefixed Key Recognizer (handles :, =, -, spaces, etc.)
    prefix_pattern = r"(?i)\b(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?"
    for m in re.finditer(prefix_pattern, text):
        matched_val = m.group(1)
        full_match = m.group(0)
        tokens.append({"item": matched_val, "type": "CREDENTIALS", "severity": "High", "confidence": 0.95})
        tokens.append({"item": full_match, "type": "CREDENTIALS", "severity": "High", "confidence": 0.95})

    # 2. Known Cloud & Security Token Signatures
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

    # 3. Standalone High-Entropy Security Token Scanner
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


# Helper: Local Fallback Regex Scanner (If Presidio is not fully initialized)
def fallback_regex_scanner(text: str) -> List[Dict[str, Any]]:
    entities = []
    
    # Run multi-delimiter and high entropy token detector
    entities.extend(detect_all_tokens_and_keys(text))
    
    # Check for emails
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
    for email in emails:
        entities.append({"item": email, "type": "EMAIL_ADDRESS", "severity": "High", "confidence": 0.95})
        
    # Check for Phone Numbers
    phone_numbers = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", text)
    for phone in phone_numbers:
        entities.append({"item": phone, "type": "PHONE_NUMBER", "severity": "Medium", "confidence": 0.90})

    # Check for Dates
    dates = re.findall(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b", text)
    for d in dates:
        entities.append({"item": d, "type": "DATE_TIME", "severity": "Medium", "confidence": 0.85})
        
    # Check for Addresses
    addresses = re.findall(r"\b\d{1,5}\s+[A-Za-z0-9\s#.,-]+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Way|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Circle|Cir)\b(?:,\s*[A-Za-z0-9\s]+)*(?:\s+[A-Z]{2})?(?:\s+\d{5})?", text)
    for addr in addresses:
        entities.append({"item": addr, "type": "ADDRESS", "severity": "Medium", "confidence": 0.85})

    # Check for Projects
    projects = re.findall(r"\bProject\s+Apollo\b", text, re.IGNORECASE)
    for p in projects:
        entities.append({"item": p, "type": "CLIENT_PROJECT_DATA", "severity": "Medium", "confidence": 0.90})

    # Check for specific names like Saketh
    names = re.findall(r"\bSaketh\b", text, re.IGNORECASE)
    for n in names:
        entities.append({"item": n, "type": "PERSON", "severity": "Medium", "confidence": 0.90})
        
    # Check for internal URLs (.corp)
    urls = re.findall(r"[a-zA-Z0-9-_.]+\.corp\b\S*", text)
    for url in urls:
        entities.append({"item": url, "type": "INTERNAL_URL", "severity": "High", "confidence": 0.90})

    # Check for salary figures (e.g. $15,000)
    salaries = re.findall(r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?", text)
    for sal in salaries:
        entities.append({"item": sal, "type": "FINANCIAL_DATA", "severity": "Medium", "confidence": 0.85})

    return entities


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(request: AnalyzeRequest):
    prompt_text = request.prompt
    logger.info(f"Analyzing prompt: {prompt_text[:50]}...")
    
    findings = []
    
    # Always include high-entropy & multi-delimiter token scan results
    findings.extend(detect_all_tokens_and_keys(prompt_text))
    
    # 1. Try Presidio Scanning
    if analyzer:
        try:
            results = analyzer.analyze(text=prompt_text, language="en")
            for res in results:
                # Extract the literal value of the matched token
                matched_item = prompt_text[res.start:res.end]
                
                # Map Presidio Entity types to standard naming
                entity_type = res.entity_type
                severity = "Medium"
                
                # Determine Severity based on type
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
        # Fallback to local custom regex scanner if Presidio isn't loaded
        findings.extend(fallback_regex_scanner(prompt_text))
        
    # Filter findings:
    # 1. Skip locations/addresses if they contain the word "example" (case-insensitive)
    # We DO NOT skip API keys or credentials even if they contain "example" (e.g. sk-test-EXAMPLE-DO-NOT-USE-123456)
    filtered_findings = []
    for f in findings:
        item_lower = f["item"].lower()
        ftype = f["type"].upper()
        
        if ("ADDRESS" in ftype or "LOCATION" in ftype) and any(x in item_lower for x in ["example", "testville", "zz"]):
            logger.info(f"Filtering out example address placeholder: {f['item']}")
            continue
            
        filtered_findings.append(f)

    # Deduplicate findings by item
    seen = set()
    deduped_findings = []
    for f in filtered_findings:
        if f["item"] not in seen:
            seen.add(f["item"])
            deduped_findings.append(f)

    # 2. Advanced Calibrated Risk Engine calculation (0 - 100) & Dynamic Assessment Generator
    if not deduped_findings:
        risk_score = 5
        risk_level = "LOW RISK"
        reason = "SAFE: No sensitive keys, credentials, or PII detected. Prompt is safe to transmit."
    else:
        # Category risk weight matrix
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

        # Find highest base severity weight
        base_weights = [category_weights.get(f["type"].upper(), 40) for f in deduped_findings]
        max_base = max(base_weights)
        
        # Incremental penalty for multiple sensitive items
        extra_items_count = len(deduped_findings) - 1
        calculated_score = max_base + (extra_items_count * 4)
        risk_score = min(99, calculated_score)

        # Generate accurate, itemized security explanations
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

    # Map back to API schema
    mapped_entities = [
        EntityInfo(
            item=f["item"],
            type=f["type"],
            severity=f["severity"],
            confidence=f["confidence"]
        ) for f in deduped_findings
    ]

    return AnalyzeResponse(
        riskScore=risk_score,
        riskLevel=risk_level,
        reason=reason,
        entities=mapped_entities
    )

@app.post("/rewrite", response_model=RewriteResponse)
async def rewrite_prompt(request: RewriteRequest):
    prompt_text = request.prompt
    entities = request.entities
    model_name = request.model or "phi4-mini"
    
    logger.info(f"Rewriting prompt with model {model_name}: {prompt_text[:50]}...")
    
    # 1. Formulate System Prompt with strict guidelines from prompt.txt
    system_prompt = (
        "You are an AI Security Gateway agent. Your task is to rewrite the user's input prompt "
        "to be completely safe for transmission to a public AI assistant (ChatGPT/Claude/Gemini/Copilot).\n\n"
        "Strict rules:\n"
        "1. Preserve the user's core task, request, and programming logic.\n"
        "2. Redact and generalize all private entities, credentials, names, URLs, phone numbers, dates of birth, addresses, and figures. "
        "Use general category placeholders like [Email Address], [Phone Number], [Date of Birth], [Address], [API Key], [Name], [Account Number], [Salary], or generic terms like 'the client' or 'internal project'.\n"
        "3. Never reproduce API keys, passwords, credentials, or actual phone numbers.\n"
        "4. Do NOT change the requested task or code structure itself.\n"
        "5. Output ONLY the safe rewritten prompt. Do NOT explain your changes. Do NOT add notes or introductory headers."
    )
    
    # 2. Compile list of entities as instruction context
    entities_summary = ", ".join([f"'{e['item']}' (Type: {e['type']})" for e in entities])
    
    user_prompt = (
        f"Original Prompt: {prompt_text}\n\n"
        f"Sensitive Entities to Redact/Generalize: {entities_summary}\n\n"
        f"Safe Rewritten Prompt:"
    )

    # 3. Request local Ollama daemon with a tight timeout
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
                    llm_output = "\n".join(lines[1:-1])
            if len(llm_output) > 5:
                safe_prompt = llm_output
                logger.info(f"Ollama rewrite received: {safe_prompt[:50]}...")
        else:
            used_model = "Deterministic Sanitizer Engine"
            logger.warning(f"Ollama returned status {response.status_code}. Using deterministic sanitizer.")
    except Exception as e:
        used_model = "Deterministic Sanitizer Engine"
        logger.warning(f"Ollama connection/timeout ({e}). Using deterministic sanitizer.")

    # 4. Mandatory Guarantee Pass: Deterministic String Replacement on all detected entities
    sorted_entities = sorted(entities, key=lambda x: len(x.get("item", "")), reverse=True)
    
    for ent in sorted_entities:
        item = ent.get("item", "")
        if not item or len(item.strip()) == 0:
            continue
        etype = ent.get("type", "").upper()
        
        # Determine placeholder
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
        elif "URL" in etype:
            placeholder = "[Internal URL]"
        elif "PROJECT" in etype:
            placeholder = "[Internal Project]"
        elif "SALARY" in etype or "FINANCIAL" in etype:
            placeholder = "[Salary]"
            
        safe_prompt = re.sub(re.escape(item), placeholder, safe_prompt)

    # 5. Secondary Regex & Token Scrubbing Pass: catch any remaining raw emails, tokens, API keys, phone numbers, or dates
    safe_prompt = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[Email Address]", safe_prompt)
    safe_prompt = re.sub(r"(?i)\b(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bAQ\.[a-zA-Z0-9._\-]{15,}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bAIzaSy[a-zA-Z0-9._\-]{33}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\bsk-[a-zA-Z0-9-]{12,}\b", "[API Key]", safe_prompt)
    safe_prompt = re.sub(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[Phone Number]", safe_prompt)
    safe_prompt = re.sub(r"\b\d{4}[-/]\d{2}[-/]\d{2}\b", "[Date of Birth]", safe_prompt)

    # Scrub standalone high-entropy security tokens
    token_words = re.findall(r"\b[a-zA-Z0-9._\-]{20,}\b", safe_prompt)
    for tw in token_words:
        if not (tw.startswith("http://") or tw.startswith("https://") or tw.isdigit()):
            if (any(c.isupper() for c in tw) and any(c.islower() for c in tw) and (any(c.isdigit() for c in tw) or any(c in "._-" for c in tw))):
                safe_prompt = re.sub(re.escape(tw), "[API Key]", safe_prompt)

    logger.info(f"Final sanitized rewrite prompt ready ({used_model}).")
    return RewriteResponse(safePrompt=safe_prompt, modelUsed=used_model)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

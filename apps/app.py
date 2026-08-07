import logging
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

from PII_filter.PII_filter import perform_pii_analysis, perform_pii_rewrite
from file_scanner.file_scanner import extract_text_from_file

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurePromptApp")

app = FastAPI(title="SecurePrompt Security & Rewrite Backend")

# Enable CORS for React frontend on port 3000
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    model: Optional[str] = "phi4-mini"

class RewriteResponse(BaseModel):
    safePrompt: str
    modelUsed: str


# [CHALLENGE 7 SOLUTION]: Dynamic Ollama Discovery with Fallback Defaults
@app.get("/models")
async def get_local_models():
    """Fetch list of locally installed Ollama models from http://localhost:11434/api/tags"""
    try:
        res = requests.get("http://localhost:11434/api/tags", timeout=2.5)
        if res.status_code == 200:
            data = res.json()
            models = [m["name"] for m in data.get("models", [])]
            if models:
                logger.info(f"Discovered local Ollama models: {models}")
                return {"models": models, "source": "Ollama Local Engine"}
    except Exception as e:
        logger.warning(f"Could not fetch Ollama models via HTTP: {e}")
        
    return {"models": ["phi4-mini:latest", "llama2-uncensored:7b", "llama3.1:latest"], "source": "Fallback Defaults"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(request: AnalyzeRequest):
    prompt_text = request.prompt
    logger.info(f"Analyzing prompt: {prompt_text[:50]}...")
    
    result = perform_pii_analysis(prompt_text)
    
    mapped_entities = [
        EntityInfo(
            item=f["item"],
            type=f["type"],
            severity=f["severity"],
            confidence=f["confidence"]
        ) for f in result["deduped_findings"]
    ]

    return AnalyzeResponse(
        riskScore=result["risk_score"],
        riskLevel=result["risk_level"],
        reason=result["reason"],
        entities=mapped_entities
    )


@app.post("/analyze-file", response_model=AnalyzeResponse)
async def analyze_file(file: UploadFile = File(...)):
    logger.info(f"Analyzing file: {file.filename}...")
    file_bytes = await file.read()
    
    extraction_result = extract_text_from_file(file_bytes, file.filename)
    
    if not extraction_result["success"]:
        # FAIL CLOSED on extraction failure
        return AnalyzeResponse(
            riskScore=100,
            riskLevel="CRITICAL RISK",
            reason=f"CRITICAL SECURITY RISK: File extraction failed ({extraction_result.get('error', 'Unknown')}). File blocked.",
            entities=[EntityInfo(item=file.filename, type="BLOCKED_FILE", severity="High", confidence=1.0)]
        )
    
    extracted_text = extraction_result["text"]
    logger.info(f"Extracted {len(extracted_text)} chars from {file.filename} via {extraction_result.get('source', 'unknown')}")
    
    # Send extracted text to EXISTING untouched pipeline
    result = perform_pii_analysis(extracted_text)
    
    mapped_entities = [
        EntityInfo(
            item=f["item"],
            type=f["type"],
            severity=f["severity"],
            confidence=f["confidence"]
        ) for f in result["deduped_findings"]
    ]

    return AnalyzeResponse(
        riskScore=result["risk_score"],
        riskLevel=result["risk_level"],
        reason=result["reason"],
        entities=mapped_entities
    )

from fastapi import Form
import json
class RewriteFileResponse(BaseModel):
    success: bool
    data: Optional[str] = None
    mimeType: Optional[str] = None
    error: Optional[str] = None

from file_scanner.file_scanner import redact_file

@app.post("/rewrite-file", response_model=RewriteFileResponse)
async def rewrite_file_endpoint(file: UploadFile = File(...), entities: str = Form(...)):
    logger.info(f"Rewriting file: {file.filename}...")
    file_bytes = await file.read()
    try:
        entities_list = json.loads(entities)
    except json.JSONDecodeError:
        return RewriteFileResponse(success=False, error="Invalid entities JSON")
        
    result = redact_file(file_bytes, file.filename, entities_list)
    return RewriteFileResponse(**result)


@app.post("/rewrite", response_model=RewriteResponse)
async def rewrite_prompt(request: RewriteRequest):
    prompt_text = request.prompt
    entities = request.entities
    model_name = request.model or "phi4-mini"
    
    logger.info(f"Rewriting prompt with model {model_name}: {prompt_text[:50]}...")
    
    result = perform_pii_rewrite(prompt_text, entities, model_name)
    
    return RewriteResponse(
        safePrompt=result["safe_prompt"],
        modelUsed=result["used_model"]
    )

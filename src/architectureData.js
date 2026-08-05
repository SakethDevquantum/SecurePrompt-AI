// Single source of truth for the SecurePrompt & SentinelPrompt AI architecture
// Derived STRICTLY from prompt.txt and idealogy.jpg. No components are invented.

export const nodesData = [
  {
    id: "user",
    title: "1. User Action (Employee)",
    category: "frontend",
    subtitle: "Prompt Paste or Send Trigger",
    description: "Employee types or pastes a prompt into a public AI chatbot (ChatGPT, Claude, Gemini, or Copilot).",
    inputs: ["Raw prompt input containing potential PII or confidential company data"],
    outputs: ["Paste event / Send prompt action triggered in browser"],
    details: [
      "User interacts with standard chatbot interface",
      "Paste or type operation intercepts prompt before network transmission"
    ],
    traceability: {
      text: "prompt.txt Lines 60-68 (Workflow 1: User -> Opens ChatGPT / Claude / Gemini -> Types Prompt)",
      image: "idealogy.jpg Section 1: User Action (Employee - Pastes prompt into ChatGPT / Claude / Gemini / Copilot)"
    }
  },
  {
    id: "extension",
    title: "2. Browser Extension",
    category: "frontend",
    subtitle: "Chrome Extension (Manifest V3)",
    description: "Intercepts prompt, captures input locally, blocks external transmission temporarily, and triggers the analysis pipeline.",
    inputs: ["Intercepted raw prompt string"],
    outputs: ["Encrypted prompt sent to FastAPI backend"],
    details: [
      "Content Script: Captures prompt before submission",
      "Background Service Worker: Handles extension communication and API requests",
      "Prevents prompt from being sent to public AI servers until vetted"
    ],
    traceability: {
      text: "prompt.txt Lines 69-76 (Chrome Extension Manifest V3, Content Script captures prompt, Background Service Worker handles communication)",
      image: "idealogy.jpg Section 2: Browser Extension (Extension Activates, Capture Prompt, Block External Transmission, Trigger Analysis Pipeline)"
    }
  },
  {
    id: "fastapi",
    title: "3. FastAPI Backend",
    category: "backend",
    subtitle: "Security Gate Gateway",
    description: "Exposes public HTTPS endpoints to recieve prompt data and coordinates the analysis pipeline and LLM rewriting.",
    inputs: ["Raw prompt payload from extension"],
    outputs: ["Dispatched prompt to analysis pipelines, returns results back to extension UI"],
    details: [
      "Hosts '/rewrite' and security evaluation endpoints",
      "Interfaces with local detection engines and LLMs"
    ],
    traceability: {
      text: "prompt.txt Lines 78-86 (Send Prompt -> FastAPI Backend, FastAPI -> Prompt Analysis Pipeline)",
      image: "idealogy.jpg Section 3: Tier 0 Fast Pattern Scanner & FastAPI Backend integration"
    }
  },
  {
    id: "pattern_scanner",
    title: "4. Fast Pattern Scanner (Tier 0)",
    category: "pipeline",
    subtitle: "Regex & Keyword Rules",
    description: "Executes lightweight scanning for immediate high-confidence patterns like API keys, credentials, and internal urls.",
    inputs: ["Raw prompt string"],
    outputs: ["Instantly identified credentials/secrets (Bypasses Tier 1 if clear and low risk)"],
    details: [
      "Regex Rules: Matches structured patterns",
      "Secrets & API Keys, High Entropy Strings",
      "Credentials & Company Keywords, Internal URLs",
      "If no match found, prompt can be sent directly (Low Risk)"
    ],
    traceability: {
      text: "prompt.txt Lines 91-95 (Regex Engine & Custom Rules / Recognizers)",
      image: "idealogy.jpg Section 3: Tier 0 - Fast Pattern Scanner (Regex Rules, Secrets & API Keys, High Entropy Strings, Credentials, Company Keywords, Internal URLs)"
    }
  },
  {
    id: "entity_detection",
    title: "5. PII & Entity Detection (Tier 1)",
    category: "pipeline",
    subtitle: "Microsoft Presidio & spaCy Engine",
    description: "Uses Microsoft Presidio backed by spaCy models and Regex engines to perform Named Entity Recognition (NER) on PII data.",
    inputs: ["Raw prompt string"],
    outputs: ["Structured classification of detected entities with confidence scores"],
    details: [
      "Microsoft Presidio (Open-source PII library)",
      "spaCy Engine for NER models",
      "Regex Engine fallback",
      "Detects: PII (Name, Email, Phone, Aadhaar, PAN), Financial Data (Salary, Bank, Cards), Credentials, Healthcare, Legal, and Source Code Assets"
    ],
    traceability: {
      text: "prompt.txt Lines 7-9 & 91-95 (Microsoft Presidio, Regex Engine, public PII detection examples)",
      image: "idealogy.jpg Section 4: Tier 1 - PII & Entity Detection (Microsoft Presidio, spaCy, Regex Engine, Detects: PII, Financial Data, Credentials, Healthcare/Legal/Source Code)"
    }
  },
  {
    id: "knowledge_base",
    title: "6. Enterprise Knowledge Base",
    category: "backend",
    subtitle: "Custom Recognition Store",
    description: "Contains enterprise-specific names and terms to feed the custom recognizers, preventing leaks of internal corporate assets.",
    inputs: ["Query from Custom Rules Engine"],
    outputs: ["Reference lists of enterprise entities to match"],
    details: [
      "Client Names, Project Names, Product Names",
      "Employee IDs, Departments, Confidential Keywords",
      "Company Policies, Internal Documents, Business Strategies, Revenue & Financials, Roadmaps"
    ],
    traceability: {
      text: "prompt.txt Lines 41-42 (custom enterprise detection rules, Custom Rules / Recognizers)",
      image: "idealogy.jpg Section 5: Enterprise Knowledge Base (Client Names, Project Names, Product Names, Employee IDs, Departments, Confidential Keywords, etc.)"
    }
  },
  {
    id: "entity_extraction",
    title: "7. Structured Entity Extraction",
    category: "backend",
    subtitle: "JSON Generator",
    description: "Normalizes the detections from Tier 0, Tier 1, and custom rules into a structured JSON schema detailing entity, type, severity, and confidence.",
    inputs: ["Heterogeneous raw detections list"],
    outputs: ["Standardized JSON structured findings"],
    details: [
      "Example Schema: { 'entity': 'Apollo', 'type': 'Internal Project', 'severity': 'High', 'confidence': 98 }"
    ],
    traceability: {
      text: "prompt.txt Lines 98-108 (Detected Entities list: PII, Email, Phone, API Keys, JWT, Credentials, Client Data, Internal Projects, Internal URLs)",
      image: "idealogy.jpg Section 6: Structured Entity Extraction (Convert Findings into Structured JSON)"
    }
  },
  {
    id: "risk_engine",
    title: "8. Risk Assessment & Policy Engine",
    category: "backend",
    subtitle: "Risk Score & Explanation Engine",
    description: "Calculates an overall risk score from 0-100 across multiple risk dimensions, mapping findings to LOW, MEDIUM, or HIGH risk categories.",
    inputs: ["Structured JSON entities metadata"],
    outputs: ["Overall risk score, risk dimensions analysis, explanation & reasoning text"],
    details: [
      "Risk Dimensions: PII, Business Secret, Credential, Financial, Healthcare, Source Code, Policy Violation Risk",
      "Maps threat severity to numerical risk values (0-100)",
      "Generates explanatory reasoning on why each entity is sensitive"
    ],
    traceability: {
      text: "prompt.txt Lines 111-120 (Risk Engine -> Risk Score 0–100 -> LOW / MEDIUM / HIGH -> Explanation)",
      image: "idealogy.jpg Section 7: Risk Assessment & Policy Engine (Risk Dimensions, Overall Risk Score, HIGH RISK banner)"
    }
  },
  {
    id: "warning_ui",
    title: "9. Security Decision Popup (UI)",
    category: "frontend",
    subtitle: "Browser Warning User Interface",
    description: "A dark theme interactive popup overlaying the browser window. Educates the employee on the detected items and presents two clear options.",
    inputs: ["Risk Score, Detected Items, Reasonings, and Recommendations"],
    outputs: ["User choice: Generate Safe Prompt OR Send Original Prompt OR Cancel"],
    details: [
      "Displays Risk Score (e.g. 91/100) and Detected Items details",
      "Explains the business impact and recommendations",
      "Offers Choice A: 'Generate Safe Prompt' (Recommended)",
      "Offers Choice B: 'Send Original Prompt' (Requires user acknowledgment of risk)",
      "Offers Choice C: 'Cancel'"
    ],
    traceability: {
      text: "prompt.txt Lines 123-135 (Workflow 3: Browser Warning UI, user selects 'Send Original' or 'Generate Safe Prompt')",
      image: "idealogy.jpg Section 8: Security Decision Popup (What We Show, User Choices: Generate Safe Prompt, Send Original Prompt, Cancel)"
    }
  },
  {
    id: "rewrite_pipeline",
    title: "10. Safe Prompt Pipeline (LLM)",
    category: "backend",
    subtitle: "Contextual LLM Rewriter",
    description: "Leverages open-source LLMs (Llama 3.1 or Phi-4-mini) to rewrite the prompt. Uses deterministic replacement combined with contextual inference.",
    inputs: ["Original prompt, system rules, and list of sensitive entities"],
    outputs: ["Privacy-Safe prompt rewritten while preserving original user intent"],
    details: [
      "System Prompt rules: Preserve user intent, remove sensitive information, generalize private entities (e.g. 'Project Apollo' to 'internal project'), never reproduce credentials, do not change task",
      "Stages: Deterministic Replacement -> Phi-4-mini Context Rewriter -> Validation & Re-Scanning -> Safe Prompt Preview"
    ],
    traceability: {
      text: "prompt.txt Lines 159-184 (Workflow 4: Original Prompt + Sensitive Entities + System Prompt rules -> Llama 3.1 / Phi-4-mini -> Privacy-Safe Prompt -> Chrome Extension)",
      image: "idealogy.jpg Section 9A: Safe Prompt Pipeline (Deterministic Replacement, Phi-4-mini Context Rewriter, Validation & Re-Scanning, Safe Prompt Preview)"
    }
  },
  {
    id: "final_warning",
    title: "11. Final Warning (If Original)",
    category: "frontend",
    subtitle: "Acknowledge Risks Block",
    description: "An optional warning modal triggered if the user decides to bypass security and send the original, sensitive prompt.",
    inputs: ["Original prompt, Risk summary info"],
    outputs: ["User consent to proceed, releasing original prompt to chatbot"],
    details: [
      "Flow: Show Final Risk Summary -> User Confirms -> Original Prompt is Sent"
    ],
    traceability: {
      text: "prompt.txt Lines 47 & 133-134 ('Send Original' option after understanding risk / warnings)",
      image: "idealogy.jpg Section 9B: Final Warning (If Original: Show Final Risk Summary, User Confirms, Original Prompt is Sent)"
    }
  },
  {
    id: "destination",
    title: "12. Final Destination",
    category: "frontend",
    subtitle: "Public AI Chatbots",
    description: "The targeted external AI assistant interface where the final, sanitized or user-confirmed original prompt is executed.",
    inputs: ["Privacy-Safe Prompt OR Approved Original Prompt"],
    outputs: ["External Chatbot execution (ChatGPT, Claude, Gemini, or Copilot)"],
    details: [
      "All analysis preceding this occurs locally/on controlled server; nothing is transmitted to public bots without explicit user consent or sanitation."
    ],
    traceability: {
      text: "prompt.txt Lines 152-157 (Send Prompt -> ChatGPT / Claude / Gemini)",
      image: "idealogy.jpg Section 10: Final Destination (If Safe Prompt Selected / If Original Prompt Confirmed, Chatbot receives prompt)"
    }
  }
];

export const workflowsData = {
  extensionFlow: [
    { from: "user", to: "extension", label: "User inputs raw prompt" },
    { from: "extension", to: "fastapi", label: "Sends prompt via API request" },
    { from: "fastapi", to: "pattern_scanner", label: "Launches Tier 0 check" },
    { from: "fastapi", to: "entity_detection", label: "Launches Tier 1 Presidio/spaCy scan" },
    { from: "entity_detection", to: "knowledge_base", label: "Looks up custom corporate lists" },
    { from: "pattern_scanner", to: "entity_extraction", label: "Passes matches" },
    { from: "entity_detection", to: "entity_extraction", label: "Passes matches" },
    { from: "entity_extraction", to: "risk_engine", label: "Passes JSON of findings" },
    { from: "risk_engine", to: "warning_ui", label: "Sends risk analysis score & explanations" }
  ],
  userDecisionFlow: {
    safeChoice: [
      { from: "warning_ui", to: "rewrite_pipeline", label: "User clicks 'Generate Safe Prompt'" },
      { from: "rewrite_pipeline", to: "warning_ui", label: "Returns Privacy-Safe prompt for preview/approval" },
      { from: "warning_ui", to: "destination", label: "User approves & sends safe prompt to AI Chatbot" }
    ],
    originalChoice: [
      { from: "warning_ui", to: "final_warning", label: "User clicks 'Send Original'" },
      { from: "final_warning", to: "destination", label: "User confirms warning & sends raw prompt to AI Chatbot" }
    ]
  }
};

export const deploymentData = {
  backend: [
    { step: 1, name: "GitHub", desc: "Source code repository for FastAPI backend codebase" },
    { step: 2, name: "Docker", desc: "Containers packaged with FastAPI backend environment and libraries" },
    { step: 3, name: "FastAPI Backend", desc: "Running within container, exposing security endpoints" },
    { step: 4, name: "Render", desc: "Hosting platform hosting the containerized backend" },
    { step: 5, name: "Public HTTPS API", desc: "Secured HTTPS entry point accessible by the Chrome Extension" }
  ],
  llm: [
    { step: 1, name: "Llama 3.1 / Phi-4-mini", desc: "Open-source LLMs configured with strict prompt rewriting instructions" },
    { step: 2, name: "Ollama / vLLM", desc: "Local or VM LLM orchestration engine serving LLM weights" },
    { step: 3, name: "Local GPU / GPU VM", desc: "Hardware hosting the vLLM/Ollama server for quick prompt inferences" },
    { step: 4, name: "FastAPI /rewrite", desc: "Endpoint querying the LLM engine to get clean prompt output" }
  ]
};

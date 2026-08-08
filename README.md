# SecurePrompt AI Gateway (Project Apollo)

SecurePrompt AI is an enterprise-grade security gateway designed to intercept, analyze, and sanitize sensitive data before it reaches public AI models like ChatGPT or Claude. It ensures that PII, credentials, financial details, and proprietary data are never inadvertently leaked into external AI training pipelines.

## 🚀 Key Features

*   **Real-time Interception**: A robust Chrome extension that seamlessly intercepts text prompts, file uploads (PDF, DOCX, TXT, Images), and drag-and-drop actions directly on AI chatbot interfaces.
*   **Advanced PII Detection**: Powered by a custom Python backend (utilizing Microsoft Presidio), it accurately identifies a wide array of sensitive data including Emails, API Keys, Passwords, Aadhaar, PAN, Credit Card CVVs, and even High-Risk Threat phrases.
*   **Intelligent Redaction & Rewriting**: Safely redacts sensitive data and uses local, privacy-first LLMs (via Ollama, supporting models like `phi4-mini` and `llama3.1`) to rewrite prompts into privacy-safe alternatives without losing the context of the user's request.
*   **Offline/Local Fallback Redactor**: The extension features a deterministic local regex engine that provides zero-downtime protection even if the backend server is temporarily unavailable.
*   **Interactive React Sandbox UI**: A beautifully crafted React dashboard that lets developers simulate AI chat flows, visualize risk scores, and monitor backend HTTP network logs in real-time.

## 📂 Architecture Overview

*   **`extension/`**: Contains the Chrome Extension logic. `content.js` handles DOM interception, file catching, UI overlays, and offline fallback filtering. `intercept.js` acts as a deep-world bypass script to hook into native file pickers.
*   **`PII_filter/`**: The Python intelligence core. Uses Presidio Analyzer to calculate exact risk scores (0-100) and severity weightings for intercepted entities.
*   **`file_scanner/`**: Dedicated python module to parse and extract text from various file structures (including documents and OCR for images) before sending it to the PII engine.
*   **`Main/main.py`**: The FastAPI backend server. It orchestrates HTTP requests from the extension, routing them through the PII filter and Ollama LLM endpoints.
*   **`src/`**: The React + Vite frontend application acting as the SecurePrompt Security Gateway Sandbox.

## 🛠️ Getting Started

### 1. Start the FastAPI Backend
Ensure you have your Python environment set up with the required dependencies (see `requirements.txt`).
```bash
python Main/main.py
```
*Runs on http://127.0.0.1:8000*

### 2. Start the React UI Sandbox
```bash
npm install
npm run dev
```

### 3. Load the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `extension/` directory in this project.
4. Open a chatbot (e.g., ChatGPT) to see the live risk widget and interception overlays in action!

## 🛡️ Security Posture
SecurePrompt operates on a zero-trust model. Anything flagged as `HIGH RISK` immediately triggers a secondary blocking popup. Users are given the option to download a fully sanitized file (Option A) or, in critical bypass scenarios, force a transmission (Option B) which immediately sends the payload while clearing security flags.

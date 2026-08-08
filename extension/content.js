// SecurePrompt Content Interceptor Script
// Injected into Chatbot pages to capture and redirect prompts locally before network send

console.log("[SecurePrompt] Injected successfully. Monitoring text inputs...");

// Helper: Check if current page or DOM container is an active AI Chatbot platform
function isAIChatbotActive() {
  const url = window.location.href.toLowerCase();
  const title = document.title.toLowerCase();
  
  const knownChatDomains = [
    "chatgpt.com", "openai.com", "claude.ai", "gemini.google.com",
    "copilot.microsoft.com", "grok.com", "x.ai", "perplexity.ai",
    "poe.com", "huggingface.co", "deepseek.com", "mistral.ai", "character.ai",
    "canva.com", "v0.dev", "bolt.new"
  ];
  
  const hasDomain = knownChatDomains.some(d => url.includes(d));
  const hasTitleKeyword = /chatgpt|claude|gemini|copilot|grok|perplexity|poe|deepseek|ai chat|assistant|canva|magic studio/.test(title);
  const hasInput = getChatInput() !== null;

  return hasDomain || hasTitleKeyword || hasInput;
}

// Helper: Locate standard & custom chatbot input elements
function getChatInput() {
  // 1. Primary selectors (ChatGPT, Claude, Gemini, Grok, Perplexity, DeepSeek, Poe, Canva AI)
  const primarySelectors = [
    '#prompt-textarea',
    'textarea[data-id]',
    'div.ProseMirror[contenteditable="true"]',
    'div[data-placeholder*="Claude"]',
    'textarea[placeholder*="ChatGPT"]',
    'textarea[placeholder*="Claude"]',
    'textarea[data-testid*="grok"]',
    'textarea[placeholder*="Ask"]',
    'textarea[placeholder*="Message"]',
    'textarea[placeholder*="Describe"]'
  ];

  for (const sel of primarySelectors) {
    const el = document.querySelector(sel);
    if (el) return el;
  }

  // 2. Active element if it's editable
  if (document.activeElement && isEditableElement(document.activeElement)) {
    return document.activeElement.closest ? document.activeElement.closest('[contenteditable="true"], textarea') || document.activeElement : document.activeElement;
  }

  // 3. Fallback: Any textarea or contenteditable inside a form or chat container
  const formInput = document.querySelector('form textarea, form [contenteditable="true"]');
  if (formInput) return formInput;

  // 4. Universal heuristic fallback
  const candidates = document.querySelectorAll('textarea, div[contenteditable="true"], input[type="text"]');
  for (const el of candidates) {
    const ph = (el.getAttribute("placeholder") || el.getAttribute("data-placeholder") || el.getAttribute("aria-label") || "").toLowerCase();
    const idClass = (el.id + " " + el.className).toLowerCase();
    
    if (/prompt|message|ask|chat|ai|assistant|copilot|claude|gemini|grok|gpt|deepseek|reply|describe|generate/.test(ph) ||
        /prompt|chat-input|chat-textarea|ai-input|composer|message-input|user-input/.test(idClass)) {
      return el;
    }
  }

  return candidates.length > 0 ? candidates[0] : null;
}

// Helper: Determine if an element is strictly the Chat Input's Send / Submit button
function isSendButton(el) {
  if (!el) return false;

  let btn = (el.tagName === "BUTTON" || el.getAttribute("role") === "button") ? el : (el.closest ? el.closest('button, [role="button"]') : null);
  if (!btn) return false;

  const testId = (btn.getAttribute("data-testid") || "").toLowerCase();
  const aria = (btn.getAttribute("aria-label") || "").toLowerCase();
  const type = (btn.getAttribute("type") || "").toLowerCase();

  // 1. Explicit ChatGPT / Grok / Claude send button testids or aria-labels
  if (testId === "send-button" || testId.includes("send-button") || testId.includes("grok-send")) return true;
  if (/^send(\s+prompt|\s+message)?$/i.test(aria.trim()) || aria === "send prompt" || aria === "send message" || aria === "send") return true;

  // 2. Submit button inside chat composer form
  const parentComposer = btn.closest ? btn.closest('form, [class*="composer"], fieldset') : null;
  if (parentComposer) {
    if (type === "submit" || testId.includes("send") || /send|submit/i.test(aria)) {
      return true;
    }
  }

  return false;
}

// Helper: Check if an element is editable
function isEditableElement(el) {
  if (!el) return false;
  if (el.tagName === "TEXTAREA" || (el.tagName === "INPUT" && el.type === "text")) return true;
  if (el.isContentEditable || el.getAttribute("contenteditable") === "true") return true;
  if (el.closest && (el.closest('textarea') || el.closest('[contenteditable="true"]'))) return true;
  return false;
}

// Helper: Extract prompt text reliably from the input element
function getPromptText(inputElement, targetElement) {
  let text = "";

  // Always prioritize reading from inputElement first
  if (inputElement) {
    text = inputElement.value || inputElement.innerText || inputElement.textContent || "";
  }

  // Fallback to targetElement if targetElement is editable
  if (!text.trim() && targetElement && isEditableElement(targetElement)) {
    const container = targetElement.closest ? targetElement.closest('[contenteditable="true"], textarea') : targetElement;
    text = container.value || container.innerText || container.textContent || "";
  }

  return text ? text.trim() : "";
}

// [CHALLENGE 5 SOLUTION]: Global Re-entrancy Flags & Event Interception Protection to Prevent Loops
let isBypassing = false;
let bypassedPrompt = null;
let pendingUnsafeFile = null;

// Attach listeners ONLY for Enter keypress and Send button click
document.addEventListener("keydown", handleKeydown, true);
document.addEventListener("click", handleClick, true);

function handleKeydown(event) {
  if (isBypassing || (event && event.isTrusted === false)) return;
  if (event.key !== "Enter" || event.shiftKey) return;
  
  const target = event.target;
  if (!isEditableElement(target)) return;
  if (!isAIChatbotActive()) return;

  const inputEl = (target.closest ? target.closest('[contenteditable="true"], textarea') : null) || getChatInput() || target;
  const text = getPromptText(inputEl, target);

  if (text === bypassedPrompt) {
    bypassedPrompt = null;
    return;
  }

  if (pendingUnsafeFile) {
    if (document.body.textContent.includes(pendingUnsafeFile.file.name)) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      showSecurityPopup(pendingUnsafeFile.originalText, pendingUnsafeFile.analysis, inputEl, pendingUnsafeFile.file, pendingUnsafeFile.fileData);
      return;
    } else {
      pendingUnsafeFile = null;
    }
  }

  if (text && text.length > 0) {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    initiateSecurityAudit(text, inputEl);
  }
}

function handleClick(event) {
  if (isBypassing || (event && event.isTrusted === false)) return;
  if (!isAIChatbotActive()) return;

  const target = event.target;
  if (isSendButton(target)) {
    const inputEl = getChatInput() || document.querySelector('textarea, [contenteditable="true"]');
    if (inputEl) {
      const text = getPromptText(inputEl, null);
      if (text === bypassedPrompt) {
        bypassedPrompt = null;
        return;
      }
      
      if (pendingUnsafeFile) {
        if (document.body.textContent.includes(pendingUnsafeFile.file.name)) {
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation();
          showSecurityPopup(pendingUnsafeFile.originalText, pendingUnsafeFile.analysis, inputEl, pendingUnsafeFile.file, pendingUnsafeFile.fileData);
          return;
        } else {
          pendingUnsafeFile = null;
        }
      }

      if (text && text.length > 0) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        initiateSecurityAudit(text, inputEl);
      }
    }
  }
}

// [CHALLENGE 7 SOLUTION]: Deterministic Local Fallback Redactor for Offline/Timing-out Backend
function localFallbackSanitize(text, entities) {
  let safe = text || "";
  const sorted = (entities || []).slice().sort((a, b) => (b.item || "").length - (a.item || "").length);
  for (const ent of sorted) {
    if (!ent.item) continue;
    let ph = "ak_live_xYz123MockKey987"; // Default fallback if type unknown
    const etype = (ent.type || "").toUpperCase();
    if (etype.includes("EMAIL")) ph = "john_doe@example.com";
    else if (etype.includes("AADHAAR")) ph = "1234-5678-9012";
    else if (etype.includes("PAN")) ph = "ABCDE1234F";
    else if (etype.includes("BANK")) ph = "0000111122223333";
    else if (etype.includes("SSN") || etype.includes("SOCIAL")) ph = "000-00-0000";
    else if (etype.includes("PHONE") || etype.includes("NUMBER")) ph = "+91 123-456-8273";
    else if (etype.includes("DATE")) ph = "01/01/0001";
    else if (etype.includes("ADDRESS") || etype.includes("LOCATION")) ph = "123 example street, Secureville, CA 90210";
    else if (etype.includes("PERSON") || etype.includes("NAME")) ph = "john doe";
    else if (etype.includes("CREDENTIAL") || etype.includes("KEY")) ph = "ak_live_xYz123MockKey987";
    else if (etype.includes("PASSWORD")) ph = "examplepassword@temp";
    else if (etype.includes("USERNAME")) ph = "example_username";
    else if (etype.includes("CVV")) ph = "123";
    else if (etype.includes("CREDIT_CARD") || etype.includes("CARD")) ph = "1111-2222-3333-4444";
    else if (etype.includes("BLOOD")) ph = "oab+-";
    else if (etype.includes("UPI")) ph = "example_name_or_no@bank_id";
    else if (etype.includes("PASSPORT")) ph = "A1234567";
    else if (etype.includes("IP_ADDRESS")) ph = "192.168.0.1";
    else if (etype.includes("MAC")) ph = "00:00:00:00:00:00";
    else if (etype.includes("CRYPTO") || etype.includes("WALLET")) ph = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    else if (etype.includes("VEHICLE") || etype.includes("PLATE")) ph = "MH-01-AB-1234";
    else if (etype.includes("THREAT")) ph = "[THREAT BLOCKED]";
    safe = safe.split(ent.item).join(ph);
  }
  safe = safe.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "john_doe@example.com");
  safe = safe.replace(/(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?/gi, "ak_live_xYz123MockKey987");
  safe = safe.replace(/\bAQ\.[a-zA-Z0-9._\-]{15,}\b/g, "ak_live_xYz123MockKey987");
  safe = safe.replace(/\bAIzaSy[a-zA-Z0-9._\-]{33}\b/g, "ak_live_xYz123MockKey987");
  safe = safe.replace(/\bAKIA[0-9A-Z]{16}\b/g, "ak_live_xYz123MockKey987");
  safe = safe.replace(/\bsk-[a-zA-Z0-9-]{12,}\b/g, "ak_live_xYz123MockKey987");
  safe = safe.replace(/\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "+91 123-456-8273");
  safe = safe.replace(/\b\d{4}[-/]\d{2}[-/]\d{2}\b/g, "01/01/0001");
  safe = safe.replace(/\b(?:I will kill you|you will die for this|I'm going to kill you|I will end your life|You are going to die)\b/gi, "[THREAT BLOCKED]");

  // New specific regexes for precise templates
  safe = safe.replace(/\b(A|B|AB|O)[+-]\b/ig, "oab+-");
  safe = safe.replace(/\b[a-zA-Z0-9.\-_]{2,256}@(upi|okaxis|okicici|oksbi|okhdfcbank|ybl|ibl|axl|paytm|apl|axisbank|icici|hdfcbank|sbi|kotak|yesbank)\b/ig, "example_name_or_no@bank_id");
  safe = safe.replace(/\b[A-Z]{1}[0-9]{7}\b/g, "A1234567");
  safe = safe.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "000-00-0000");
  safe = safe.replace(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, "192.168.0.1");
  safe = safe.replace(/\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g, "00:00:00:00:00:00");
  safe = safe.replace(/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
  safe = safe.replace(/\b[A-Z]{2}[- ]?\d{2}[- ]?[A-Z]{1,2}[- ]?\d{4}\b/g, "MH-01-AB-1234");
  safe = safe.replace(/\b\d{10,18}\b/g, "0000111122223333");
  safe = safe.replace(/\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g, "ABCDE1234F");
  safe = safe.replace(/\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, "1234-5678-9012");
  return safe;
}

// Send input to background worker to scan
function initiateSecurityAudit(text, inputElement) {
  if (isBypassing) return;

  // Local fallback checker if background extension connection is offline or invalidated
  const runLocalFallbackAudit = () => {
    let textToAudit = text;
    const mockTemplates = [
      "examplepassword@temp", "example_username", "john_doe@example.com", "+91 123-456-8273",
      "01/01/0001", "123 example street, Secureville, CA 90210", "john doe", "ak_live_xYz123MockKey987",
      "1234-5678-9012", "ABCDE1234F", "123", "1111-2222-3333-4444", "oab+-", "example_name_or_no@bank_id",
      "A1234567", "0000111122223333", "000-00-0000", "192.168.0.1", "00:00:00:00:00:00", 
      "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "MH-01-AB-1234"
    ];
    mockTemplates.forEach(m => {
      textToAudit = textToAudit.split(m).join("");
    });

    const fallbackClean = localFallbackSanitize(textToAudit, []);
    const hasTokens = fallbackClean !== textToAudit || 
                      /\b(?:sk-|AQ\.|AIzaSy|AKIA|ghp_|hf_)[a-zA-Z0-9._\-]{10,}\b/.test(textToAudit) ||
                      /(?:api[_\s-]?key|secret|token|password)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?/i.test(textToAudit);

    if (hasTokens) {
      console.warn("[SecurePrompt] Background connection offline. Running local scanner fallback.");
      const fallbackAnalysis = {
        riskScore: 85,
        riskLevel: "HIGH RISK",
        reason: "CRITICAL SECURITY RISK: Prompt contains exposed API keys or secret credentials.",
        entities: [{ item: text.length > 30 ? text.substring(0, 30) + "..." : text, type: "CREDENTIALS", severity: "High" }]
      };
      showSecurityPopup(text, fallbackAnalysis, inputElement);
    } else {
      bypassAndSubmitImmediate(text, inputElement);
    }
  };

  try {
    if (!chrome || !chrome.runtime || !chrome.runtime.id) {
      console.warn("[SecurePrompt] Extension context invalidated. Running local scanner fallback.");
      runLocalFallbackAudit();
      return;
    }
  } catch (e) {
    console.warn("[SecurePrompt] Extension context error. Running local scanner fallback:", e);
    runLocalFallbackAudit();
    return;
  }

  console.log("[SecurePrompt] Intercepted prompt: ", text.substring(0, 40) + "...");

  // ── MALICIOUS INTENT PRE-CHECK ──────────────────────────────────────────
  // Call classify-intent FIRST. If MALICIOUS → hard stop. Otherwise → existing flow.
  const proceedWithExistingFlow = () => {
    let isHandled = false;
    // 4-second safety timeout so webpage never hangs
    const timeoutId = setTimeout(() => {
      if (!isHandled) {
        isHandled = true;
        console.warn("[SecurePrompt] Analysis timed out. Running local fallback.");
        runLocalFallbackAudit();
      }
    }, 4000);

    try {
      chrome.runtime.sendMessage({ action: "analyzePrompt", prompt: text }, (response) => {
        if (isHandled) return;
        isHandled = true;
        clearTimeout(timeoutId);

        if (chrome.runtime.lastError) {
          console.warn("[SecurePrompt] Runtime error:", chrome.runtime.lastError.message);
          runLocalFallbackAudit();
          return;
        }

        if (response && response.success) {
          const analysis = response.analysis;
          if (analysis.riskScore > 20) {
            showSecurityPopup(text, analysis, inputElement);
          } else {
            bypassAndSubmitImmediate(text, inputElement);
          }
        } else {
          console.warn("[SecurePrompt] API analysis failed. Running local fallback.");
          runLocalFallbackAudit();
        }
      });
    } catch (e) {
      if (!isHandled) {
        isHandled = true;
        clearTimeout(timeoutId);
        runLocalFallbackAudit();
      }
    }
  };

  // Pre-check: classify intent via Phi-4-mini
  try {
    chrome.runtime.sendMessage({ action: "classifyIntent", prompt: text }, (classifyResponse) => {
      if (chrome.runtime.lastError || !classifyResponse || !classifyResponse.success) {
        // If classifier fails, fall through to existing flow (fail-open for classifier only)
        console.warn("[SecurePrompt] Intent classifier unavailable. Proceeding with existing flow.");
        proceedWithExistingFlow();
        return;
      }

      if (classifyResponse.classification === "MALICIOUS") {
        showMaliciousBlockPopup(text, inputElement);
        return; // HARD STOP — do not proceed to PII analysis or submission
      }

      // REGULAR or SENSITIVE → proceed with existing PII/sensitive analysis flow
      proceedWithExistingFlow();
    });
  } catch (e) {
    console.warn("[SecurePrompt] Intent classify error:", e);
    proceedWithExistingFlow();
  }
}


// Inject warning modal directly into chatbot DOM
let securityPopupActive = false;
let currentResolve = null;

// ── MALICIOUS PROMPT BLOCK POPUP ────────────────────────────────────────────
function showMaliciousBlockPopup(text, inputElement) {
  console.warn("[SecurePrompt] MALICIOUS prompt detected. Blocking immediately.");

  // Remove the message from the input
  try {
    if (inputElement) {
      if (inputElement.tagName === "TEXTAREA" || inputElement.tagName === "INPUT") {
        const nativeSet = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")?.set
          || Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
        if (nativeSet) nativeSet.call(inputElement, "");
        else inputElement.value = "";
        inputElement.dispatchEvent(new Event("input", { bubbles: true }));
      } else {
        inputElement.innerText = "";
        inputElement.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
  } catch (e) {
    console.error("[SecurePrompt] Failed to clear input:", e);
  }

  // Remove existing overlay if any
  const existing = document.getElementById("sp-security-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "sp-security-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(15, 23, 42, 0.92);
    backdrop-filter: blur(12px);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #F8FAFC;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    background: #0F172A;
    border: 1px solid rgba(239, 68, 68, 0.4);
    border-radius: 14px;
    padding: 28px;
    max-width: 460px;
    width: 90%;
    box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.2), 0 20px 30px -10px rgba(0, 0, 0, 0.6);
  `;

  container.innerHTML = `
    <div style="display: flex; gap: 16px; margin-bottom: 20px; align-items: flex-start;">
      <div style="width: 48px; height: 48px; border-radius: 50%; background: rgba(239, 68, 68, 0.12); border: 2px solid #F87171; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#F87171" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
        </svg>
      </div>
      <div>
        <h3 style="margin: 0 0 6px 0; font-size: 16px; font-weight: 700; color: #F87171; letter-spacing: 0.3px;">Malicious Prompt Detected</h3>
        <p style="margin: 0; font-size: 13px; color: #CBD5E1; line-height: 1.6;">
          This prompt appears to contain an attempt to leak sensitive information,
          bypass security controls, inject instructions, perform phishing, or otherwise
          manipulate the AI system.
        </p>
      </div>
    </div>

    <div style="background: rgba(239, 68, 68, 0.06); border: 1px solid rgba(239, 68, 68, 0.15); border-radius: 10px; padding: 14px; margin-bottom: 20px;">
      <p style="margin: 0; font-size: 12px; color: #94A3B8; line-height: 1.5;">
        <strong style="color: #F87171; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px;">Action Taken:</strong><br>
        The message was <strong style="color: #F8FAFC;">blocked and removed</strong>. It will not be sent to any external AI provider.
      </p>
    </div>

    <button id="sp-malicious-dismiss" style="width: 100%; padding: 12px; border-radius: 8px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #F87171; font-weight: 600; font-size: 13px; cursor: pointer; transition: all 0.15s ease; letter-spacing: 0.3px;">
      Dismiss
    </button>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  document.getElementById("sp-malicious-dismiss").addEventListener("click", () => {
    overlay.remove();
    securityPopupActive = false;
  });

  // Update live widget to show malicious status
  if (typeof updateLiveWidget === "function") {
    updateLiveWidget(100, "BLOCKED");
  }
}

function cleanupPopup() {
  const existing = document.getElementById("sp-security-overlay");
  if (existing) existing.remove();
  securityPopupActive = false;
}

function showSecurityPopup(originalText, analysis, inputElement, fileObj = null, fileData = null) {
  console.log("[SecurePrompt] showSecurityPopup called. securityPopupActive is:", securityPopupActive);
  if (securityPopupActive) {
      console.warn("[SecurePrompt] Blocked showing popup because securityPopupActive is true.");
      return;
  }
  securityPopupActive = true;

  // Remove existing overlays if any
  const existing = document.getElementById("sp-security-overlay");
  if (existing) {
      console.warn("[SecurePrompt] Found existing overlay! Removing it.");
      existing.remove();
  }

  const overlay = document.createElement("div");
  overlay.id = "sp-security-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(8px);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #F8FAFC;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    background: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 14px;
    padding: 22px;
    max-width: 480px;
    width: 90%;
    box-shadow: 0 20px 30px -10px rgba(0, 0, 0, 0.6);
  `;

  const isHighRisk = analysis.riskScore >= 75;
  const badgeBorder = isHighRisk ? "#F87171" : "#FBBF24";
  const badgeBg = isHighRisk ? "rgba(239, 68, 68, 0.08)" : "rgba(245, 158, 11, 0.08)";
  const badgeBorderBox = isHighRisk ? "rgba(239, 68, 68, 0.2)" : "rgba(245, 158, 11, 0.2)";
  const badgeText = isHighRisk ? "#F87171" : "#FBBF24";
  
  const choiceAText = fileObj ? "Choice A: Mask & Download Safe File (Recommended)" : "Choice A: Generate Safe Prompt (Recommended)";
  const choiceASubText = fileObj ? "Redacts sensitive data from the file and downloads a safe version" : "Sanitizes PII and credentials using local LLM rewriter";

  // Construct UI
  container.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1E293B; padding-bottom: 12px; margin-bottom: 16px;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${badgeText};"></span>
        <h3 style="margin: 0; font-size: 13px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; color: #F8FAFC;">SecurePrompt Gateway Guard</h3>
      </div>
      <span style="font-size: 10px; font-weight: 500; color: #64748B; background: #1E293B; padding: 2px 8px; border-radius: 12px;">v1.0</span>
    </div>
    
    <div style="display: flex; gap: 14px; background: ${badgeBg}; border: 1px solid ${badgeBorderBox}; padding: 14px; border-radius: 10px; margin-bottom: 16px; align-items: flex-start;">
      <div style="width: 40px; height: 40px; border-radius: 50%; border: 2px solid ${badgeBorder}; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; color: ${badgeText}; flex-shrink: 0; background: #0F172A;">
        ${analysis.riskScore}
      </div>
      <div>
        <h4 style="margin: 0; font-size: 13px; font-weight: 700; color: ${badgeText}; letter-spacing: 0.3px;">${analysis.riskLevel} DETECTED</h4>
        <p style="margin: 5px 0 0 0; font-size: 12px; color: #F8FAFC; line-height: 1.5; font-weight: 500;">
          <strong style="color: #94A3B8; text-transform: uppercase; font-size: 10px;">Details:</strong><br>
          ${analysis.reason}
        </p>
      </div>
    </div>

    <div style="margin-bottom: 16px;">
      <h4 style="margin: 0 0 8px 0; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #64748B;">Sensitive Entities Found (${analysis.entities.length}):</h4>
      <div style="display: flex; flex-direction: column; gap: 6px; max-height: 110px; overflow-y: auto; padding-right: 2px;">
        ${analysis.entities.map(e => `
          <div style="background: #0B0F17; border: 1px solid #1E293B; padding: 8px 12px; border-radius: 8px; font-size: 11px; display: flex; justify-content: space-between; align-items: center;">
            <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #E2E8F0; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${e.item}</span>
            <span style="font-size: 9px; font-weight: 600; text-transform: uppercase; color: #38BDF8; background: rgba(14, 165, 233, 0.1); padding: 2px 6px; border-radius: 4px;">${e.type}</span>
          </div>
        `).join('')}
      </div>
    </div>

    <div style="display: flex; flex-direction: column; gap: 8px; border-top: 1px solid #1E293B; padding-top: 14px;">
      <button id="sp-btn-rewrite" style="width: 100%; padding: 11px 14px; border-radius: 8px; background: #0EA5E9; color: #FFFFFF; border: none; font-weight: 600; font-size: 12px; cursor: pointer; text-align: left; transition: opacity 0.15s ease;">
        ${choiceAText}
        <span style="display: block; font-size: 10px; opacity: 0.85; font-weight: 400; margin-top: 2px;">${choiceASubText}</span>
      </button>
      
      <button id="sp-btn-original" style="width: 100%; padding: 11px 14px; border-radius: 8px; background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); color: #F87171; font-weight: 600; font-size: 12px; cursor: pointer; text-align: left;">
        Choice B: Send Original ${fileObj ? 'File' : 'Prompt'}
        <span style="display: block; font-size: 10px; opacity: 0.85; font-weight: 400; margin-top: 2px;">Bypass blocker warning and transmit raw ${fileObj ? 'file' : 'prompt'}</span>
      </button>
      
      <button id="sp-btn-cancel" style="width: 100%; padding: 8px; border-radius: 8px; background: transparent; border: 1px solid #334155; color: #94A3B8; font-weight: 500; font-size: 11px; cursor: pointer;">
        Cancel & Edit
      </button>
    </div>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  // Attach buttons listeners
  document.getElementById("sp-btn-rewrite").addEventListener("click", () => {
    const btn = document.getElementById("sp-btn-rewrite");
    btn.innerHTML = `<span style="display: flex; align-items: center; gap: 8px;">Generating safe ${fileObj ? 'file' : 'prompt'}... <span style="display:inline-block; animation: pulse 1.5s infinite;">⏳</span></span>`;
    btn.disabled = true;

    if (fileObj) {
        chrome.runtime.sendMessage({
            action: "rewriteFile",
            fileData: fileData,
            fileName: fileObj.name,
            mimeType: fileObj.type,
            entities: analysis.entities
        }, (rewriteResponse) => {
            if (rewriteResponse && rewriteResponse.success && rewriteResponse.rewrite && rewriteResponse.rewrite.success) {
                cleanupPopup();
                
                // Trigger download of the safe file
                const safeData = rewriteResponse.rewrite.data;
                const safeMime = rewriteResponse.rewrite.mimeType;
                const prefix = "data:" + safeMime + ";base64,";
                
                const downloadLink = document.createElement("a");
                downloadLink.href = prefix + safeData;
                downloadLink.download = "safe_" + fileObj.name;
                downloadLink.click();
                
                // Toast notification instead of alert
                const toast = document.createElement("div");
                toast.innerHTML = `<strong>File Redacted!</strong><br/>SecurePrompt downloaded a safe version of your file.<br/>Please remove the original file and upload the safe one.`;
                toast.style.cssText = "position:fixed;top:20px;right:20px;background:#3B82F6;color:#fff;padding:16px 20px;border-radius:10px;z-index:999999;font-family:sans-serif;font-size:14px;box-shadow:0 10px 25px rgba(0,0,0,0.4);border-left:4px solid #10B981;line-height:1.4;";
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 6000);
            } else {
                alert("Failed to redact file. It may not be a supported file type for redaction.");
                cleanupPopup();
            }
        });
    } else {
        chrome.storage.local.get(["rewriteModel"], (res) => {
          const selectedModel = (res && res.rewriteModel) ? res.rewriteModel : "phi4-mini:latest";

          let isHandled = false;
          const timeoutId = setTimeout(() => {
            if (!isHandled) {
              isHandled = true;
              cleanupPopup();
              const safeFallback = localFallbackSanitize(originalText, analysis.entities);
              showRewriteReview(originalText, safeFallback, inputElement, analysis);
            }
          }, 6500);

          try {
            chrome.runtime.sendMessage({
              action: "rewritePrompt",
              prompt: originalText,
              entities: analysis.entities,
              model: selectedModel
            }, (rewriteResponse) => {
              if (isHandled) return;
              isHandled = true;
              clearTimeout(timeoutId);
              cleanupPopup();

              if (rewriteResponse && rewriteResponse.success && rewriteResponse.rewrite && rewriteResponse.rewrite.safePrompt) {
                showRewriteReview(originalText, rewriteResponse.rewrite.safePrompt, inputElement, analysis);
              } else {
                const safeFallback = localFallbackSanitize(originalText, analysis.entities);
                showRewriteReview(originalText, safeFallback, inputElement, analysis);
              }
            });
          } catch (e) {
            if (!isHandled) {
              isHandled = true;
              clearTimeout(timeoutId);
              cleanupPopup();
              const safeFallback = localFallbackSanitize(originalText, analysis.entities);
              showRewriteReview(originalText, safeFallback, inputElement, analysis);
            }
          }
        });
    }
  });

  document.getElementById("sp-btn-original").addEventListener("click", () => {
    cleanupPopup();
    bypassAndSubmitImmediate(originalText, inputElement, fileObj);
  });

  document.getElementById("sp-btn-cancel").addEventListener("click", () => {
    cleanupPopup();
  });
}

// Final Warning popup for Option B
function showFinalWarningPopup(originalText, analysis, inputElement, fileObj = null, fileData = null) {
  const overlay = document.createElement("div");
  overlay.id = "secure-prompt-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(4, 6, 11, 0.9);
    backdrop-filter: blur(12px);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    background: #0E1624;
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 14px;
    padding: 24px;
    max-width: 420px;
    width: 90%;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
  `;

  container.innerHTML = `
    <div style="display: flex; gap: 14px; margin-bottom: 20px;">
      <div style="color: #F87171; flex-shrink: 0; margin-top: 2px;">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><path d="M12 9v4"></path><path d="M12 17h.01"></path></svg>
      </div>
      <div>
        <h3 style="margin: 0 0 6px 0; font-size: 15px; font-weight: 700; color: #F8FAFC;">Final Warning</h3>
        <p style="margin: 0; font-size: 12px; color: #94A3B8; line-height: 1.5;">You are bypassing standard safety measures. This prompt will be transmitted unredacted to external public AI servers.</p>
      </div>
    </div>
    
    <div style="background: #080C14; border: 1px solid #1E293B; border-radius: 8px; padding: 12px; margin-bottom: 20px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #F87171;">
      Score: ${analysis.riskScore}/100. Severity Category: HIGH EXPOSURE risk.
    </div>

    <div style="display: flex; gap: 10px;">
      <button id="sp-btn-back" style="flex: 1; padding: 10px; border-radius: 8px; background: transparent; border: 1px solid #334155; color: #CBD5E1; font-weight: 600; font-size: 12px; cursor: pointer; transition: all 0.2s;">
        Go Back
      </button>
      <button id="sp-btn-send-anyway" style="flex: 1; padding: 10px; border-radius: 8px; background: #DC2626; border: none; color: #FFFFFF; font-weight: 600; font-size: 12px; cursor: pointer; transition: all 0.2s;">
        Send Anyway
      </button>
    </div>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  document.getElementById("sp-btn-back").addEventListener("click", () => {
    overlay.remove();
    showSecurityPopup(originalText, analysis, inputElement, fileObj, fileData);
  });

  document.getElementById("sp-btn-send-anyway").addEventListener("click", () => {
    overlay.remove();
    
    // Attempt to bypass UI by setting native value then submitting.
    // In chat UIs, it will briefly populate and clear.
    bypassAndSubmitImmediate(originalText, inputElement, fileObj);
    
    // Instantly hide the input text to simulate "not putting it in the chat input text"
    setTimeout(() => {
      try {
        if (inputElement) {
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")?.set 
              || Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
            if (nativeInputValueSetter) {
              nativeInputValueSetter.call(inputElement, "");
            } else {
              inputElement.value = "";
            }
            inputElement.dispatchEvent(new Event("input", { bubbles: true }));
        }
      } catch (e) {}
    }, 10);
  });
}

// Side-by-side prompt review overlay
function showRewriteReview(originalText, safeText, inputElement, analysis) {
  const overlay = document.createElement("div");
  overlay.id = "secure-prompt-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(11, 15, 23, 0.75);
    backdrop-filter: blur(8px);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #F8FAFC;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    background: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 14px;
    padding: 22px;
    max-width: 620px;
    width: 90%;
    box-shadow: 0 20px 30px -10px rgba(0, 0, 0, 0.6);
  `;

  container.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1E293B; padding-bottom: 12px; margin-bottom: 16px;">
      <h3 style="margin: 0; font-size: 13px; font-weight: 600; color: #38BDF8; letter-spacing: 0.3px;">Review Rewritten Prompt</h3>
      <span style="font-size: 10px; font-weight: 600; color: #10B981; background: rgba(16, 185, 129, 0.1); padding: 2px 8px; border-radius: 12px;">PII Cleansed</span>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
      <div style="background: #0B0F17; border: 1px solid #1E293B; padding: 12px; border-radius: 10px;">
        <span style="font-size: 10px; font-weight: 600; text-transform: uppercase; color: #F87171; display: block; margin-bottom: 6px; letter-spacing: 0.5px;">Original Prompt:</span>
        <div style="font-size: 11px; max-height: 140px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; color: #94A3B8; line-height: 1.45;">${originalText}</div>
      </div>
      <div style="background: rgba(14, 165, 233, 0.04); border: 1px solid rgba(14, 165, 233, 0.2); padding: 12px; border-radius: 10px;">
        <span style="font-size: 10px; font-weight: 600; text-transform: uppercase; color: #38BDF8; display: block; margin-bottom: 6px; letter-spacing: 0.5px;">Privacy-Safe Prompt:</span>
        <div style="font-size: 11px; max-height: 140px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; color: #F8FAFC; line-height: 1.45;">${safeText}</div>
      </div>
    </div>

    <div style="display: flex; gap: 10px; justify-content: flex-end; border-top: 1px solid #1E293B; padding-top: 14px;">
      <button id="sp-review-back" style="padding: 8px 16px; border-radius: 8px; background: transparent; border: 1px solid #334155; color: #94A3B8; font-weight: 500; font-size: 11px; cursor: pointer;">
        Go Back
      </button>
      <button id="sp-review-approve" style="padding: 8px 18px; border-radius: 8px; background: #0EA5E9; color: #FFFFFF; border: none; font-weight: 600; font-size: 11px; cursor: pointer;">
        Approve & Use Safe Prompt
      </button>
    </div>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  document.getElementById("sp-review-back").addEventListener("click", () => {
    overlay.remove();
    showSecurityPopup(originalText, analysis, inputElement);
  });

  document.getElementById("sp-review-approve").addEventListener("click", () => {
    overlay.remove();
    injectTextOnly(safeText, inputElement);
  });
}

// Input values injection
function injectTextOnly(text, inputElement) {
  bypassedPrompt = text; // Allow this exact text to bypass on next manual send

  try {
    inputElement.focus();
    if (inputElement.tagName === "TEXTAREA" || inputElement.tagName === "INPUT") {
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")?.set 
        || Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
      if (nativeInputValueSetter) {
        nativeInputValueSetter.call(inputElement, text);
      } else {
        inputElement.value = text;
      }
      inputElement.dispatchEvent(new Event("input", { bubbles: true }));
    } else {
      try {
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, text);
      } catch (e) {
        console.warn("[SecurePrompt] execCommand fallback:", e);
        inputElement.innerText = text;
        inputElement.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
  } catch (e) {
    console.error("[SecurePrompt] Text insertion error:", e);
  }
}

/// Immediately inject and trigger submission
function bypassAndSubmitImmediate(text, inputElement, fileObj = null) {
  isBypassing = true;
  pendingUnsafeFile = null;

  if (!inputElement && fileObj) {
    // The file was already attached naturally. Just click the send button to bypass.
    try {
        const buttons = document.querySelectorAll('button');
        for (const b of buttons) {
            if (isSendButton(b)) {
                b.click();
                break;
            }
        }
    } catch (e) {
        console.error("[SecurePrompt] Submission trigger error for file bypass:", e);
    }
    setTimeout(() => {
        isBypassing = false;
    }, 2500);
    return;
  } else if (!inputElement) {
    console.error("[SecurePrompt] Cannot submit: inputElement is null and no file provided.");
    return;
  }

  try {
    inputElement.focus();
    if (inputElement.tagName === "TEXTAREA" || inputElement.tagName === "INPUT") {
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")?.set 
        || Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
      if (nativeInputValueSetter) {
        nativeInputValueSetter.call(inputElement, text);
      } else {
        inputElement.value = text;
      }
      inputElement.dispatchEvent(new Event("input", { bubbles: true }));
    } else {
      try {
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, text);
      } catch (e) {
        console.warn("[SecurePrompt] execCommand fallback:", e);
        inputElement.innerText = text;
        inputElement.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
  } catch (e) {
    console.error("[SecurePrompt] Text insertion error:", e);
  }

  // Trigger submission on chatbot page with lock cleanup
  setTimeout(() => {
    try {
      const buttons = document.querySelectorAll('button');
      let submitBtn = null;
      for (const b of buttons) {
        if (isSendButton(b)) {
          submitBtn = b;
          break;
        }
      }
      
      if (submitBtn) {
        submitBtn.click();
      } else {
        // Fallback: emit enter key on input element
        if (inputElement) {
            const enterEvent = new KeyboardEvent('keydown', {
              key: 'Enter', code: 'Enter', keyCode: 13,
              which: 13, bubbles: true, cancelable: true
            });
            inputElement.dispatchEvent(enterEvent);
        }
      }
    } catch (e) {
      console.error("[SecurePrompt] Submission trigger error:", e);
    } finally {
      setTimeout(() => {
        isBypassing = false;
      }, 2500);
    }
  }, 300);
}

// --- DRAGGABLE LIVE RISK WIDGET ---
let liveWidget = null;
let liveRiskDebounce = null;
let lastAnalyzedText = "";

function createLiveWidget() {
  if (liveWidget) return liveWidget;
  if (!isAIChatbotActive()) return null;

  liveWidget = document.createElement("div");
  liveWidget.id = "sp-live-widget";
  liveWidget.style.cssText = `
    position: fixed;
    bottom: 24px;
    right: 24px;
    width: 200px;
    background: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 12px;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6);
    z-index: 999998;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #F8FAFC;
    overflow: hidden;
    user-select: none;
    opacity: 0;
    transition: opacity 0.3s ease, border-color 0.3s ease;
    display: flex;
    flex-direction: column;
  `;

  liveWidget.innerHTML = `
    <div id="sp-live-header" style="background: #1E293B; padding: 10px 14px; font-size: 11px; font-weight: 600; color: #94A3B8; display: flex; align-items: center; justify-content: space-between; cursor: grab;">
      <span style="display:flex; align-items:center; gap:8px;">
        <span id="sp-live-indicator" style="width:8px; height:8px; border-radius:50%; background:#0EA5E9; box-shadow: 0 0 6px #0EA5E9;"></span>
        SecurePrompt AI
      </span>
    </div>
    <div style="padding: 14px 16px; display: flex; flex-direction: column; gap: 6px;">
      <div style="font-size: 10px; color: #64748B; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Live Risk Score</div>
      <div id="sp-live-score" style="font-size: 28px; font-weight: 700; color: #10B981; line-height: 1;">0</div>
      <div id="sp-live-status" style="font-size: 11px; color: #10B981; font-weight: 600; margin-top: 2px;">SAFE</div>
    </div>
  `;

  document.body.appendChild(liveWidget);

  // Drag logic
  const header = liveWidget.querySelector('#sp-live-header');
  let isDragging = false, startX, startY, initialX, initialY;

  header.addEventListener("mousedown", (e) => {
    isDragging = true;
    header.style.cursor = "grabbing";
    startX = e.clientX;
    startY = e.clientY;
    const rect = liveWidget.getBoundingClientRect();
    initialX = rect.left;
    initialY = rect.top;
    e.preventDefault();
  });

  document.addEventListener("mousemove", (e) => {
    if (!isDragging) return;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;
    liveWidget.style.left = `${initialX + dx}px`;
    liveWidget.style.top = `${initialY + dy}px`;
    liveWidget.style.bottom = "auto";
    liveWidget.style.right = "auto";
  });

  document.addEventListener("mouseup", () => {
    if (isDragging) {
      isDragging = false;
      header.style.cursor = "grab";
    }
  });

  return liveWidget;
}

function updateLiveWidget(score, statusStr) {
  if (!liveWidget) createLiveWidget();
  if (!liveWidget) return;

  liveWidget.style.opacity = "1";
  
  const scoreEl = liveWidget.querySelector('#sp-live-score');
  const statusEl = liveWidget.querySelector('#sp-live-status');
  const indicatorEl = liveWidget.querySelector('#sp-live-indicator');
  
  scoreEl.innerText = score;
  
  if (score === "...") {
    scoreEl.style.color = "#94A3B8";
    statusEl.style.color = "#94A3B8";
    statusEl.innerText = statusStr || "Analyzing...";
    indicatorEl.style.background = "#94A3B8";
    indicatorEl.style.boxShadow = "0 0 6px #94A3B8";
    liveWidget.style.borderColor = "#1E293B";
    return;
  }
  
  const numScore = parseInt(score);
  statusEl.innerText = statusStr;

  if (numScore >= 75) {
    scoreEl.style.color = "#F87171";
    statusEl.style.color = "#F87171";
    indicatorEl.style.background = "#F87171";
    indicatorEl.style.boxShadow = "0 0 6px #F87171";
    liveWidget.style.borderColor = "rgba(239, 68, 68, 0.4)";
  } else if (numScore >= 40) {
    scoreEl.style.color = "#FBBF24";
    statusEl.style.color = "#FBBF24";
    indicatorEl.style.background = "#FBBF24";
    indicatorEl.style.boxShadow = "0 0 6px #FBBF24";
    liveWidget.style.borderColor = "rgba(245, 158, 11, 0.4)";
  } else {
    scoreEl.style.color = "#10B981";
    statusEl.style.color = "#10B981";
    indicatorEl.style.background = "#10B981";
    indicatorEl.style.boxShadow = "0 0 6px #10B981";
    liveWidget.style.borderColor = "rgba(16, 185, 129, 0.2)";
  }
}

// Hook into global input events to debounce and analyze
document.addEventListener("input", (e) => {
  if (!isEditableElement(e.target)) return;
  if (!isAIChatbotActive()) return;

  const inputEl = (e.target.closest ? e.target.closest('[contenteditable="true"], textarea') : null) || e.target;
  const text = getPromptText(inputEl, e.target);

  if (text === lastAnalyzedText) return;

  if (text.trim().length === 0) {
    if (liveWidget) liveWidget.style.opacity = "0";
    lastAnalyzedText = "";
    return;
  }

  // Debounce API call
  clearTimeout(liveRiskDebounce);
  
  if (!liveWidget || liveWidget.style.opacity === "0") {
    createLiveWidget();
    updateLiveWidget("...", "Typing...");
  }

  liveRiskDebounce = setTimeout(() => {
    lastAnalyzedText = text;
    updateLiveWidget("...", "Loading risk score...");

    try {
      if (!chrome || !chrome.runtime || !chrome.runtime.id) return;
      
      chrome.runtime.sendMessage({ action: "analyzePrompt", prompt: text }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
          // Local fallback check if background connection is broken or times out
          const hasTokens = /\\b(?:sk-|AQ\\.|AIzaSy|AKIA|ghp_|hf_)[a-zA-Z0-9._\\-]{10,}\\b/.test(text) ||
                            /(?:api[_\\s-]?key|secret|token|password)\\s*[:=\\-\\s]\\s*['\\"]?([a-zA-Z0-9._\\-]{10,})['\\"]?/i.test(text);
          if (hasTokens) updateLiveWidget(85, "HIGH RISK");
          else updateLiveWidget(0, "SAFE");
          return;
        }

        const score = response.analysis.riskScore;
        const level = response.analysis.riskLevel;
        updateLiveWidget(score, level);
      });
    } catch (err) {
      updateLiveWidget(0, "SAFE");
    }
  }, 600); // 600ms debounce
}, true);

// --- FILE ATTACHMENT INTERCEPTION (Image, TXT, PDF) ---
function handleFileAttachment(file, onUnsafe) {
    if (!isAIChatbotActive()) return;
    if (window.__sp_injecting_safe_file) {
        console.log("[SecurePrompt] Skipping scan for injected safe file:", file.name);
        return;
    }

    const supportedTypes = ['text/plain', 'application/pdf', 'image/png', 'image/jpeg', 'image/webp', 'image/bmp', 'image/tiff', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    // Allow if it matches type or extension
    const ext = (file.name.match(/\.[0-9a-z]+$/i) || [''])[0].toLowerCase();
    const validExts = ['.txt', '.pdf', '.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tiff', '.tif', '.docx'];
    
    if (!supportedTypes.includes(file.type) && !validExts.includes(ext)) {
        return; // Skip unsupported files
    }

    if (file.size > 10 * 1024 * 1024) {
        console.warn('[SecurePrompt] File too large for local scanning (Max 10MB)');
        return;
    }

    if (!liveWidget || liveWidget.style.opacity === "0") {
        createLiveWidget();
    }
    updateLiveWidget("...", "Scanning file...");

    const reader = new FileReader();
    reader.onload = function(e) {
        const fileData = e.target.result;
        
        try {
            chrome.runtime.sendMessage({
                action: "analyzeFile",
                fileData: fileData,
                fileName: file.name,
                mimeType: file.type
            }, (response) => {
                if (chrome.runtime.lastError || !response || !response.success) {
                    console.error("[SecurePrompt] File scan failed:", chrome.runtime.lastError || response?.error);
                    const errAnalysis = {
                        riskScore: 100, riskLevel: "CRITICAL RISK",
                        reason: "CRITICAL SECURITY RISK: File extraction failed or timed out. File blocked.",
                        entities: [{ item: file.name, type: "BLOCKED_FILE", severity: "High", confidence: 1.0 }]
                    };
                    pendingUnsafeFile = { originalText: "[Attached File: " + file.name + "]", analysis: errAnalysis, file: file, fileData: fileData };
                    showSecurityPopup("[Attached File: " + file.name + "]", errAnalysis, null, file, fileData);
                    if (onUnsafe) onUnsafe();
                    return;
                }
                
                const analysis = response.analysis;
                updateLiveWidget(analysis.riskScore, analysis.riskLevel);
                
                // Check for malicious content in file
                if (analysis.malicious === true) {
                    showMaliciousBlockPopup("[Attached File: " + file.name + "]", null);
                    if (onUnsafe) onUnsafe();
                    return;
                }
                
                if (analysis.riskScore > 20) {
                    pendingUnsafeFile = { originalText: "[Attached File: " + file.name + "]", analysis: analysis, file: file, fileData: fileData };
                    showSecurityPopup("[Attached File: " + file.name + "]", analysis, null, file, fileData);
                    if (onUnsafe) onUnsafe();
                }
            });
        } catch (err) {
            console.error("[SecurePrompt] File scan error:", err);
        }
    };
    reader.readAsDataURL(file);
}

// 1. File Input Change
document.addEventListener('change', (e) => {
    const target = e.target;
    if (target.tagName === 'INPUT' && target.type === 'file' && target.files.length > 0) {
        if (target.files[0].name.startsWith("safe_")) return;
        
        handleFileAttachment(target.files[0], null);
    }
}, true);

// 2. Drag and Drop
document.addEventListener('drop', (e) => {
    if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        if (e.dataTransfer.files[0].name.startsWith("safe_")) return;
        
        handleFileAttachment(e.dataTransfer.files[0], null);
    }
}, true);

// 3. Paste
document.addEventListener('paste', (e) => {
    if (e.clipboardData && e.clipboardData.files.length > 0) {
        if (e.clipboardData.files[0].name.startsWith("safe_")) return;
        
        handleFileAttachment(e.clipboardData.files[0], null);
    }
}, true);

// 4. Intercept Off-DOM Inputs and File System API (Mid-conversation dynamically created inputs)
window.addEventListener('message', (event) => {
    if (event.source === window && event.data && event.data.type === 'SECURE_PROMPT_FILE_INJECTED') {
        const file = event.data.file;
        if (file && !file.name.startsWith("safe_")) {
            handleFileAttachment(file, null);
        }
    }
});

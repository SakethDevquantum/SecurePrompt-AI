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
  // 1. Specific Known AI Chatbot Selectors (ChatGPT, Claude, Gemini, Grok, Perplexity, DeepSeek, Poe, Canva AI, Copilot)
  const specificSelectors = [
    '#prompt-textarea',
    'textarea[placeholder*="ChatGPT"]',
    'textarea[placeholder*="Claude"]',
    'div[data-placeholder*="Claude"]',
    'div.ProseMirror[contenteditable="true"]',
    'textarea[placeholder*="Ask"]',
    'textarea[placeholder*="Message"]',
    'textarea[placeholder*="Describe"]',
    'textarea[placeholder*="Grok"]',
    'textarea[placeholder*="Perplexity"]',
    'textarea[placeholder*="DeepSeek"]',
    'textarea[data-testid*="grok"]',
    'div[contenteditable="true"]#prompt-textarea',
    'div[contenteditable="true"][data-placeholder*="prompt"]',
    'div[contenteditable="true"][data-placeholder*="Message"]',
    'div[contenteditable="true"][aria-label*="Canva"]',
    'div[contenteditable="true"][aria-label*="Assistant"]',
    'div[contenteditable="true"][aria-label*="Chat"]'
  ];
  
  const specific = document.querySelector(specificSelectors.join(', '));
  if (specific) return specific;

  // 2. Universal Heuristic Query: Any textarea or contenteditable div with AI/Chat keywords
  const candidates = document.querySelectorAll('textarea, div[contenteditable="true"], input[type="text"]');
  for (const el of candidates) {
    const ph = (el.getAttribute("placeholder") || el.getAttribute("data-placeholder") || el.getAttribute("aria-label") || "").toLowerCase();
    const idClass = (el.id + " " + el.className).toLowerCase();
    
    const isAiKeyword = /prompt|message|ask|chat|ai|assistant|copilot|claude|gemini|grok|gpt|deepseek|reply|describe|generate/.test(ph) ||
                        /prompt|chat-input|chat-textarea|ai-input|composer|message-input|user-input/.test(idClass);
                        
    if (isAiKeyword) {
      return el;
    }
  }

  return null;
}

function getSubmitButton() {
  const specificSelectors = [
    'button[data-testid*="send"]',
    'button[data-testid*="grok"]',
    'button[aria-label*="Send"]',
    'button[aria-label*="send"]',
    'button[aria-label*="Submit"]',
    'button[aria-label*="Generate"]',
    'button[aria-label*="Ask"]',
    'button[class*="send"]',
    'button[id*="send"]',
    'button[class*="Submit"]',
    'button[id*="submit"]'
  ];
  
  const btn = document.querySelector(specificSelectors.join(', '));
  if (btn) return btn;

  const buttons = document.querySelectorAll('button');
  for (const b of buttons) {
    const label = (b.getAttribute("aria-label") || b.innerText || b.className || "").toLowerCase();
    if (/send|submit|generate|ask/.test(label)) {
      return b;
    }
  }

  return null;
}

// Helper: Check if an element is editable
function isEditableElement(el) {
  if (!el) return false;
  if (el.tagName === "TEXTAREA" || (el.tagName === "INPUT" && el.type === "text")) return true;
  if (el.isContentEditable || el.getAttribute("contenteditable") === "true") return true;
  if (el.closest && (el.closest('textarea') || el.closest('[contenteditable="true"]'))) return true;
  return false;
}

// Helper: Extract prompt text reliably
function getPromptText(inputElement, targetElement) {
  let text = "";
  if (targetElement) {
    const container = targetElement.closest ? targetElement.closest('[contenteditable="true"], textarea') : null;
    const activeEl = container || targetElement;
    text = activeEl.value || activeEl.innerText || activeEl.textContent || "";
  }
  if (!text.trim() && inputElement) {
    text = inputElement.value || inputElement.innerText || inputElement.textContent || "";
  }
  return text ? text.trim() : "";
}

// Global re-entrancy lock to prevent submit loops & freezes
let isBypassing = false;

// Attach listeners to DOM
document.addEventListener("keydown", handleKeydown, true);
document.addEventListener("click", handleClick, true);

function handleKeydown(event) {
  if (isBypassing) return;
  if (event.key !== "Enter" || event.shiftKey) return;
  
  const target = event.target;
  if (!isEditableElement(target)) return;
  if (!isAIChatbotActive()) return;

  const inputEl = (target.closest ? target.closest('[contenteditable="true"], textarea') : null) || getChatInput() || target;
  const text = getPromptText(inputEl, target);

  if (text && text.length > 0) {
    event.preventDefault();
    event.stopPropagation();
    initiateSecurityAudit(text, inputEl);
  }
}

function handleClick(event) {
  if (isBypassing) return;
  if (!isAIChatbotActive()) return;

  const target = event.target;
  const btn = target.closest ? target.closest('button, [role="button"]') : null;
  if (!btn) return;

  const btnLabel = (btn.getAttribute("aria-label") || btn.innerText || btn.className || btn.id || "").toLowerCase();
  const isSendBtn = /send|submit|generate|ask|grok/.test(btnLabel) || (btn.querySelector && btn.querySelector('svg'));

  if (isSendBtn) {
    const inputEl = getChatInput() || document.querySelector('textarea, [contenteditable="true"]');
    if (inputEl) {
      const text = getPromptText(inputEl, target);
      if (text && text.length > 0) {
        event.preventDefault();
        event.stopPropagation();
        initiateSecurityAudit(text, inputEl);
      }
    }
  }
}

// Local fallback sanitizer in JS if background/LLM connection fails
function localFallbackSanitize(text, entities) {
  let safe = text || "";
  const sorted = (entities || []).slice().sort((a, b) => (b.item || "").length - (a.item || "").length);
  for (const ent of sorted) {
    if (!ent.item) continue;
    let ph = `[${ent.type || "Private Data"}]`;
    const etype = (ent.type || "").toUpperCase();
    if (etype.includes("EMAIL")) ph = "[Email Address]";
    else if (etype.includes("PHONE") || etype.includes("NUMBER")) ph = "[Phone Number]";
    else if (etype.includes("DATE")) ph = "[Date of Birth]";
    else if (etype.includes("ADDRESS") || etype.includes("LOCATION")) ph = "[Address]";
    else if (etype.includes("PERSON") || etype.includes("NAME")) ph = "[Name]";
    else if (etype.includes("CREDENTIAL") || etype.includes("KEY")) ph = "[API Key]";
    safe = safe.split(ent.item).join(ph);
  }
  safe = safe.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[Email Address]");
  safe = safe.replace(/(?:api[_\s-]?key|secret|token|bearer|auth|password|passwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?/gi, "[API Key]");
  safe = safe.replace(/\bAQ\.[a-zA-Z0-9._\-]{15,}\b/g, "[API Key]");
  safe = safe.replace(/\bAIzaSy[a-zA-Z0-9._\-]{33}\b/g, "[API Key]");
  safe = safe.replace(/\bAKIA[0-9A-Z]{16}\b/g, "[API Key]");
  safe = safe.replace(/\bsk-[a-zA-Z0-9-]{12,}\b/g, "[API Key]");
  safe = safe.replace(/\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "[Phone Number]");
  safe = safe.replace(/\b\d{4}[-/]\d{2}[-/]\d{2}\b/g, "[Date of Birth]");
  return safe;
}

// Send input to background worker to scan
function initiateSecurityAudit(text, inputElement) {
  if (isBypassing) return;
  
  if (!chrome.runtime || !chrome.runtime.id) {
    console.warn("[SecurePrompt] Extension context invalidated. Bypassing check.");
    bypassAndSubmit(text, inputElement);
    return;
  }

  console.log("[SecurePrompt] Intercepted prompt: ", text.substring(0, 40) + "...");

  let isHandled = false;
  // 4-second safety timeout so webpage never hangs
  const timeoutId = setTimeout(() => {
    if (!isHandled) {
      isHandled = true;
      console.warn("[SecurePrompt] Analysis timed out. Releasing input.");
      bypassAndSubmit(text, inputElement);
    }
  }, 4000);

  try {
    chrome.runtime.sendMessage({ action: "analyzePrompt", prompt: text }, (response) => {
      if (isHandled) return;
      isHandled = true;
      clearTimeout(timeoutId);

      if (chrome.runtime.lastError) {
        console.warn("[SecurePrompt] Runtime error:", chrome.runtime.lastError.message);
        bypassAndSubmit(text, inputElement);
        return;
      }

      if (response && response.success) {
        const analysis = response.analysis;
        if (analysis.riskScore >= 40) {
          showSecurityPopup(text, analysis, inputElement);
        } else {
          bypassAndSubmit(text, inputElement);
        }
      } else {
        console.warn("[SecurePrompt] API analysis failed. Bypassing check.");
        bypassAndSubmit(text, inputElement);
      }
    });
  } catch (e) {
    if (!isHandled) {
      isHandled = true;
      clearTimeout(timeoutId);
      console.warn("[SecurePrompt] Messaging error:", e);
      bypassAndSubmit(text, inputElement);
    }
  }
}

// Inject warning modal directly into chatbot DOM
function showSecurityPopup(originalText, analysis, inputElement) {
  // Remove existing overlays if any
  const existing = document.getElementById("secure-prompt-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "secure-prompt-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(4, 6, 11, 0.85);
    backdrop-filter: blur(4px);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Outfit', sans-serif;
    color: #F3F4F6;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    background: #0E1624;
    border: 1px solid #1F2E47;
    border-radius: 12px;
    padding: 24px;
    max-width: 480px;
    width: 90%;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
  `;

  // Construct UI
  container.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #1F2E47; padding-bottom: 12px; margin-bottom: 16px;">
      <span style="color: #EF4444; font-size: 20px;">⚠️</span>
      <h3 style="margin: 0; font-size: 14px; font-weight: bold; text-transform: uppercase;">SecurePrompt Gateway Alert</h3>
    </div>
    
    <div style="display: flex; gap: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); padding: 12px; border-radius: 8px; margin-bottom: 16px; align-items: center;">
      <div style="width: 42px; height: 42px; border-radius: 50%; border: 2px solid #EF4444; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 14px; color: #EF4444; shrink: 0;">
        ${analysis.riskScore}
      </div>
      <div>
        <h4 style="margin: 0; font-size: 12px; font-weight: bold; color: #EF4444;">OVERALL RISK: ${analysis.riskLevel}</h4>
        <p style="margin: 2px 0 0 0; font-size: 11px; color: #9CA3AF;">${analysis.reason}</p>
      </div>
    </div>

    <div style="margin-bottom: 16px;">
      <h4 style="margin: 0 0 6px 0; font-size: 11px; font-weight: bold; text-transform: uppercase; color: #9CA3AF;">Sensitive Items Identified:</h4>
      <div style="display: flex; flex-direction: column; gap: 4px; max-height: 100px; overflow-y: auto;">
        ${analysis.entities.map(e => `
          <div style="background: #080C14; border: 1px solid #1F2E47; padding: 6px 10px; border-radius: 6px; font-size: 11px; display: flex; justify-content: space-between; align-items: center;">
            <span style="font-family: monospace; font-weight: bold; color: #F3F4F6;">${e.item}</span>
            <span style="font-size: 9px; font-weight: bold; color: #F59E0B;">${e.type}</span>
          </div>
        `).join('')}
      </div>
    </div>

    <div style="display: flex; flex-direction: column; gap: 8px; border-top: 1px solid #1F2E47; padding-top: 12px;">
      <button id="sp-btn-rewrite" style="width: 100%; padding: 10px; border-radius: 8px; background: #38BDF8; color: #080C14; border: none; font-weight: bold; font-size: 12px; cursor: pointer; text-align: left;">
        Choice A: Generate Safe Prompt (Recommended)
        <span style="display: block; font-size: 9px; opacity: 0.8; font-weight: normal; margin-top: 2px;">Sanitizes PII and identifiers using Llama 3.1</span>
      </button>
      
      <button id="sp-btn-original" style="width: 100%; padding: 10px; border-radius: 8px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #EF4444; font-weight: bold; font-size: 12px; cursor: pointer; text-align: left;">
        Choice B: Send Original Prompt
        <span style="display: block; font-size: 9px; opacity: 0.8; font-weight: normal; margin-top: 2px;">Bypass blocker warnings</span>
      </button>
      
      <button id="sp-btn-cancel" style="width: 100%; padding: 8px; border-radius: 8px; background: transparent; border: 1px solid #6B7280; color: #9CA3AF; font-weight: bold; font-size: 11px; cursor: pointer;">
        Cancel & Edit
      </button>
    </div>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  // Attach buttons listeners
  document.getElementById("sp-btn-rewrite").addEventListener("click", () => {
    const btn = document.getElementById("sp-btn-rewrite");
    btn.innerText = "Rewriting with Llama 3.1...";
    btn.disabled = true;
    btn.style.opacity = "0.7";

    let isHandled = false;
    const timeoutId = setTimeout(() => {
      if (!isHandled) {
        isHandled = true;
        overlay.remove();
        const safeFallback = localFallbackSanitize(originalText, analysis.entities);
        showRewriteReview(originalText, safeFallback, inputElement);
      }
    }, 6000);

    try {
      chrome.runtime.sendMessage({
        action: "rewritePrompt",
        prompt: originalText,
        entities: analysis.entities
      }, (rewriteResponse) => {
        if (isHandled) return;
        isHandled = true;
        clearTimeout(timeoutId);
        overlay.remove();

        if (rewriteResponse && rewriteResponse.success && rewriteResponse.rewrite && rewriteResponse.rewrite.safePrompt) {
          showRewriteReview(originalText, rewriteResponse.rewrite.safePrompt, inputElement);
        } else {
          const safeFallback = localFallbackSanitize(originalText, analysis.entities);
          showRewriteReview(originalText, safeFallback, inputElement);
        }
      });
    } catch (e) {
      if (!isHandled) {
        isHandled = true;
        clearTimeout(timeoutId);
        overlay.remove();
        const safeFallback = localFallbackSanitize(originalText, analysis.entities);
        showRewriteReview(originalText, safeFallback, inputElement);
      }
    }
  });

  document.getElementById("sp-btn-original").addEventListener("click", () => {
    overlay.remove();
    showFinalWarning(originalText, analysis, inputElement);
  });

  document.getElementById("sp-btn-cancel").addEventListener("click", () => {
    overlay.remove();
  });
}

// Side-by-side prompt review overlay
function showRewriteReview(originalText, safeText, inputElement) {
  const overlay = document.createElement("div");
  overlay.id = "secure-prompt-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(4, 6, 11, 0.85);
    backdrop-filter: blur(4px);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Outfit', sans-serif;
    color: #F3F4F6;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    background: #0E1624;
    border: 1px solid #1F2E47;
    border-radius: 12px;
    padding: 24px;
    max-width: 600px;
    width: 90%;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
  `;

  container.innerHTML = `
    <div style="border-bottom: 1px solid #1F2E47; padding-bottom: 12px; margin-bottom: 16px;">
      <h3 style="margin: 0; font-size: 14px; font-weight: bold; color: #38BDF8;">Review Rewritten Prompt</h3>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
      <div style="background: #080C14; border: 1px solid #1F2E47; padding: 10px; border-radius: 8px;">
        <span style="font-size: 9px; font-weight: bold; color: #EF4444; display: block; margin-bottom: 4px;">ORIGINAL PROMPT:</span>
        <div style="font-size: 11px; max-height: 120px; overflow-y: auto; font-family: monospace;">${originalText}</div>
      </div>
      <div style="background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.2); padding: 10px; border-radius: 8px;">
        <span style="font-size: 9px; font-weight: bold; color: #38BDF8; display: block; margin-bottom: 4px;">PRIVACY-SAFE PROMPT:</span>
        <div style="font-size: 11px; max-height: 120px; overflow-y: auto; font-family: monospace; color: #FFF;">${safeText}</div>
      </div>
    </div>

    <div style="display: flex; gap: 8px; justify-content: flex-end; border-top: 1px solid #1F2E47; padding-top: 12px;">
      <button id="sp-review-back" style="padding: 8px 16px; border-radius: 6px; background: transparent; border: 1px solid #6B7280; color: #9CA3AF; font-weight: bold; font-size: 11px; cursor: pointer;">
        Go Back
      </button>
      <button id="sp-review-approve" style="padding: 8px 16px; border-radius: 6px; background: #38BDF8; color: #080C14; border: none; font-weight: bold; font-size: 11px; cursor: pointer;">
        Approve & Send
      </button>
    </div>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  document.getElementById("sp-review-back").addEventListener("click", () => {
    overlay.remove();
  });

  document.getElementById("sp-review-approve").addEventListener("click", () => {
    overlay.remove();
    bypassAndSubmit(safeText, inputElement);
  });
}

// Final warning confirm bypass
function showFinalWarning(originalText, analysis, inputElement) {
  const overlay = document.createElement("div");
  overlay.id = "secure-prompt-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(4, 6, 11, 0.90);
    backdrop-filter: blur(4px);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Outfit', sans-serif;
    color: #F3F4F6;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    background: #0E1624;
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 12px;
    padding: 24px;
    max-width: 400px;
    width: 95%;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
  `;

  container.innerHTML = `
    <div style="display: flex; gap: 12px; margin-bottom: 16px;">
      <span style="color: #EF4444; font-size: 24px;">⚠️</span>
      <div>
        <h3 style="margin: 0; font-size: 14px; font-weight: bold; color: #FFF;">Final Warning (If Original Selected)</h3>
        <p style="margin: 4px 0 0 0; font-size: 11px; color: #9CA3AF; line-height: 1.4;">
          Sending sensitive values like API keys or financial records violates corporate compliance models.
        </p>
      </div>
    </div>

    <div style="display: flex; gap: 8px; justify-content: flex-end; border-top: 1px solid #1F2E47; padding-top: 12px;">
      <button id="sp-warn-back" style="padding: 8px 16px; border-radius: 6px; background: transparent; border: 1px solid #6B7280; color: #9CA3AF; font-weight: bold; font-size: 11px; cursor: pointer;">
        Go Back
      </button>
      <button id="sp-warn-confirm" style="padding: 8px 16px; border-radius: 6px; background: #EF4444; color: #FFF; border: none; font-weight: bold; font-size: 11px; cursor: pointer;">
        Confirm & Send Original
      </button>
    </div>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  document.getElementById("sp-warn-back").addEventListener("click", () => {
    overlay.remove();
  });

  document.getElementById("sp-warn-confirm").addEventListener("click", () => {
    overlay.remove();
    bypassAndSubmit(originalText, inputElement);
  });
}

// Input values injection and simulate submission
function bypassAndSubmit(text, inputElement) {
  isBypassing = true;

  try {
    inputElement.focus();
    if (inputElement.tagName === "TEXTAREA" || inputElement.tagName === "INPUT") {
      inputElement.value = text;
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
      const submitBtn = getSubmitButton();
      if (submitBtn) {
        submitBtn.click();
      } else {
        const enterEvent = new KeyboardEvent("keydown", {
          key: "Enter",
          code: "Enter",
          keyCode: 13,
          which: 13,
          bubbles: true,
          cancelable: true
        });
        inputElement.dispatchEvent(enterEvent);
      }
    } catch (e) {
      console.error("[SecurePrompt] Submit trigger error:", e);
    } finally {
      setTimeout(() => {
        isBypassing = false;
      }, 800);
    }
  }, 150);
}

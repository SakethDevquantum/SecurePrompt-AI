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

  // Local fallback checker if background extension connection is offline or invalidated
  const runLocalFallbackAudit = () => {
    const fallbackClean = localFallbackSanitize(text, []);
    const hasTokens = fallbackClean !== text || 
                      /\b(?:sk-|AQ\.|AIzaSy|AKIA|ghp_|hf_)[a-zA-Z0-9._\-]{10,}\b/.test(text) ||
                      /(?:api[_\s-]?key|secret|token|password)\s*[:=\-\s]\s*['\"]?([a-zA-Z0-9._\-]{10,})['\"]?/i.test(text);

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
    max-width: 480px;
    width: 90%;
    box-shadow: 0 20px 30px -10px rgba(0, 0, 0, 0.6);
  `;

  const isHighRisk = analysis.riskScore >= 75;
  const badgeBorder = isHighRisk ? "#F87171" : "#FBBF24";
  const badgeBg = isHighRisk ? "rgba(239, 68, 68, 0.08)" : "rgba(245, 158, 11, 0.08)";
  const badgeBorderBox = isHighRisk ? "rgba(239, 68, 68, 0.2)" : "rgba(245, 158, 11, 0.2)";
  const badgeText = isHighRisk ? "#F87171" : "#FBBF24";

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
        Choice A: Generate Safe Prompt (Recommended)
        <span style="display: block; font-size: 10px; opacity: 0.85; font-weight: 400; margin-top: 2px;">Sanitizes PII and credentials using local LLM rewriter</span>
      </button>
      
      <button id="sp-btn-original" style="width: 100%; padding: 11px 14px; border-radius: 8px; background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); color: #F87171; font-weight: 600; font-size: 12px; cursor: pointer; text-align: left;">
        Choice B: Send Original Prompt
        <span style="display: block; font-size: 10px; opacity: 0.85; font-weight: 400; margin-top: 2px;">Bypass blocker warning and transmit raw prompt</span>
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
    btn.disabled = true;
    btn.style.opacity = "0.7";

    chrome.storage.local.get(["rewriteModel"], (res) => {
      const selectedModel = (res && res.rewriteModel) ? res.rewriteModel : "phi4-mini:latest";
      btn.innerText = `Rewriting with ${selectedModel}...`;

      let isHandled = false;
      const timeoutId = setTimeout(() => {
        if (!isHandled) {
          isHandled = true;
          overlay.remove();
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
          overlay.remove();

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
          overlay.remove();
          const safeFallback = localFallbackSanitize(originalText, analysis.entities);
          showRewriteReview(originalText, safeFallback, inputElement, analysis);
        }
      }
    });
  });

  document.getElementById("sp-btn-original").addEventListener("click", () => {
    overlay.remove();
    showFinalWarningPopup(originalText, analysis, inputElement);
  });

  document.getElementById("sp-btn-cancel").addEventListener("click", () => {
    overlay.remove();
  });
}

// Final Warning popup for Option B
function showFinalWarningPopup(originalText, analysis, inputElement) {
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
    showSecurityPopup(originalText, analysis, inputElement);
  });

  document.getElementById("sp-btn-send-anyway").addEventListener("click", () => {
    overlay.remove();
    
    // Attempt to bypass UI by setting native value then submitting.
    // In chat UIs, it will briefly populate and clear.
    bypassAndSubmitImmediate(originalText, inputElement);
    
    // Instantly hide the input text to simulate "not putting it in the chat input text"
    setTimeout(() => {
      try {
        const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")?.set 
          || Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
        if (nativeInputValueSetter) {
          nativeInputValueSetter.call(inputElement, "");
        } else {
          inputElement.value = "";
        }
        inputElement.dispatchEvent(new Event("input", { bubbles: true }));
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

// Immediately inject and trigger submission
function bypassAndSubmitImmediate(text, inputElement) {
  isBypassing = true;

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
      }, 2500);
    }
  }, 150);
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

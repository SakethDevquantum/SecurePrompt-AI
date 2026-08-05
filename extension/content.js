// SecurePrompt Content Interceptor Script
// Injected into Chatbot pages to capture and redirect prompts locally before network send

console.log("[SecurePrompt] Injected successfully. Monitoring text inputs...");

// Helper: Locate standard chatbot input elements
function getChatInput() {
  // Try specific prompt ID/class selectors first (ChatGPT, Claude, Gemini)
  const specific = document.querySelector(
    '#prompt-textarea, textarea[placeholder*="ChatGPT"], textarea[placeholder*="Claude"], [contenteditable="true"]#prompt-textarea, [data-placeholder*="prompt"]'
  );
  if (specific) return specific;

  // Fallback to general structures
  return document.querySelector(
    'textarea, div[contenteditable="true"]'
  );
}

function getSubmitButton() {
  // Matches typical send/submit buttons on modern chatbot UI platforms
  return document.querySelector(
    'button[data-testid*="send"], button[aria-label*="Send"], button[aria-label*="send"], button[class*="send"], button[id*="send"], button[class*="Submit"], button[id*="submit"]'
  );
}

// Attach listeners to DOM
document.addEventListener("keydown", handleKeydown, true);
document.addEventListener("click", handleClick, true);

function handleKeydown(event) {
  const input = getChatInput();
  if (input && (event.target === input || input.contains(event.target)) && event.key === "Enter" && !event.shiftKey) {
    const text = input.value || input.innerText;
    if (text.trim().length > 0) {
      event.preventDefault();
      event.stopPropagation();
      initiateSecurityAudit(text, input);
    }
  }
}

function handleClick(event) {
  const button = getSubmitButton();
  if (button && button.contains(event.target)) {
    const input = getChatInput();
    if (input) {
      const text = input.value || input.innerText;
      if (text.trim().length > 0) {
        event.preventDefault();
        event.stopPropagation();
        initiateSecurityAudit(text, input);
      }
    }
  }
}

// Send input to background worker to scan
function initiateSecurityAudit(text, inputElement) {
  console.log("[SecurePrompt] Intercepted prompt: ", text.substring(0, 40) + "...");
  
  chrome.runtime.sendMessage({ action: "analyzePrompt", prompt: text }, (response) => {
    if (response && response.success) {
      const analysis = response.analysis;
      if (analysis.riskScore >= 40) {
        // High/Medium Risk detected! Render modal warning
        showSecurityPopup(text, analysis, inputElement);
      } else {
        // Safe prompt, release it to the platform
        bypassAndSubmit(text, inputElement);
      }
    } else {
      // API call failed, bypass and send default
      console.warn("[SecurePrompt] API analysis failed. Bypassing check.");
      bypassAndSubmit(text, inputElement);
    }
  });
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
    document.getElementById("sp-btn-rewrite").innerText = "Rewriting with Llama 3.1...";
    chrome.runtime.sendMessage({
      action: "rewritePrompt",
      prompt: originalText,
      entities: analysis.entities
    }, (rewriteResponse) => {
      overlay.remove();
      if (rewriteResponse && rewriteResponse.success) {
        showRewriteReview(originalText, rewriteResponse.rewrite.safePrompt, inputElement);
      } else {
        alert("Failed to query local LLM rewriter.");
      }
    });
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
  inputElement.focus();
  
  if (inputElement.tagName === "TEXTAREA" || inputElement.tagName === "INPUT") {
    inputElement.value = text;
    // Dispatch input event for framework bindings to capture changes
    inputElement.dispatchEvent(new Event("input", { bubbles: true }));
  } else {
    // For contenteditable elements, use execCommand to ensure React/Lexical framework state updates correctly
    try {
      document.execCommand("selectAll", false, null);
      document.execCommand("insertText", false, text);
    } catch (e) {
      console.warn("[SecurePrompt] execCommand fallback:", e);
      inputElement.innerText = text;
      inputElement.dispatchEvent(new Event("input", { bubbles: true }));
    }
  }

  // Trigger submission on chatbot page
  setTimeout(() => {
    const submitBtn = getSubmitButton();
    if (submitBtn) {
      submitBtn.click();
    } else {
      // Fallback submit by pressing Enter inside the element
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
  }, 150);
}

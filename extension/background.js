// SecurePrompt Chrome Extension Background Service Worker
// Manages backend API communication with FastAPI

const BACKEND_URL = "http://127.0.0.1:8000";

// Listen to intercept requests from Content Scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzePrompt") {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    fetch(`${BACKEND_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: request.prompt }),
      signal: controller.signal
    })
    .then(res => {
      clearTimeout(timeoutId);
      if (!res.ok) throw new Error("Backend connection failed");
      return res.json();
    })
    .then(data => {
      sendResponse({ success: true, analysis: data });
    })
    .catch(err => {
      clearTimeout(timeoutId);
      console.error("Error in analyze API:", err);
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep message channel open for async response
  }

  if (request.action === "rewritePrompt") {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6500);

    fetch(`${BACKEND_URL}/rewrite`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        prompt: request.prompt, 
        entities: request.entities,
        model: request.model || "phi4-mini"
      }),
      signal: controller.signal
    })
    .then(res => {
      clearTimeout(timeoutId);
      if (!res.ok) throw new Error("Backend connection failed");
      return res.json();
    })
    .then(data => {
      sendResponse({ success: true, rewrite: data });
    })
    .catch(err => {
      clearTimeout(timeoutId);
      console.error("Error in rewrite API:", err);
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep channel open
  }
});

// SecurePrompt Chrome Extension Background Service Worker
// Manages backend API communication with FastAPI

const BACKEND_URL = "http://127.0.0.1:8000";

// Listen to intercept requests from Content Scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzePrompt") {
    // Forward the prompt to local FastAPI analyzer
    fetch(`${BACKEND_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: request.prompt })
    })
    .then(res => {
      if (!res.ok) throw new Error("Backend connection failed");
      return res.json();
    })
    .then(data => {
      sendResponse({ success: true, analysis: data });
    })
    .catch(err => {
      console.error("Error in analyze API:", err);
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep message channel open for async response
  }

  if (request.action === "rewritePrompt") {
    // Request local LLM rewrite via FastAPI
    fetch(`${BACKEND_URL}/rewrite`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        prompt: request.prompt, 
        entities: request.entities,
        model: request.model || "phi4-mini"
      })
    })
    .then(res => {
      if (!res.ok) throw new Error("Backend connection failed");
      return res.json();
    })
    .then(data => {
      sendResponse({ success: true, rewrite: data });
    })
    .catch(err => {
      console.error("Error in rewrite API:", err);
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep channel open
  }
});

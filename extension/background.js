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

  if (request.action === "analyzeFile") {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 45000); // 45 seconds for OCR/PDF

    // Convert base64 to Blob
    let base64Data = request.fileData;
    if (base64Data.includes(',')) {
      base64Data = base64Data.split(',')[1];
    }
    
    const binary = atob(base64Data);
    const array = [];
    for (let i = 0; i < binary.length; i++) {
      array.push(binary.charCodeAt(i));
    }
    const blob = new Blob([new Uint8Array(array)], {type: request.mimeType});

    const formData = new FormData();
    formData.append("file", blob, request.fileName);

    fetch(`${BACKEND_URL}/analyze-file`, {
      method: "POST",
      body: formData,
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
      console.error("Error in analyze-file API:", err);
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep message channel open for async response
  }

  if (request.action === "rewritePrompt") {
    // [CHALLENGE 7 SOLUTION]: 6.5s Abort Controller Timeout for Async LLM Calls
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

  if (request.action === "rewriteFile") {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); 

    // Convert base64 to Blob
    let base64Data = request.fileData;
    if (base64Data.includes(',')) {
      base64Data = base64Data.split(',')[1];
    }
    
    const binary = atob(base64Data);
    const array = [];
    for (let i = 0; i < binary.length; i++) {
      array.push(binary.charCodeAt(i));
    }
    const blob = new Blob([new Uint8Array(array)], {type: request.mimeType});

    const formData = new FormData();
    formData.append("file", blob, request.fileName);
    formData.append("entities", JSON.stringify(request.entities));

    fetch(`${BACKEND_URL}/rewrite-file`, {
      method: "POST",
      body: formData,
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
      console.error("Error in rewrite-file API:", err);
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep channel open
  }
});

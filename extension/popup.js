// SecurePrompt extension settings manager
document.addEventListener("DOMContentLoaded", () => {
  const modelSelect = document.getElementById("model-select");

  const populateModels = (models, savedModel) => {
    modelSelect.innerHTML = "";
    models.forEach(m => {
      const opt = document.createElement("option");
      opt.value = m;
      opt.textContent = m;
      if (m === savedModel) opt.selected = true;
      modelSelect.appendChild(opt);
    });
  };

  // Fetch local models from backend endpoint /models
  chrome.storage.local.get(["rewriteModel"], (result) => {
    const saved = result.rewriteModel || "";
    fetch("http://127.0.0.1:8000/models")
      .then(res => res.json())
      .then(data => {
        const models = (data && data.models && data.models.length > 0) ? data.models : ["phi4-mini:latest", "llama2-uncensored:7b", "llama3.1:latest"];
        populateModels(models, saved || models[0]);
        if (!saved) {
          chrome.storage.local.set({ rewriteModel: models[0] });
        }
      })
      .catch(err => {
        console.warn("Could not fetch models from backend:", err);
        const fallbacks = ["phi4-mini:latest", "llama2-uncensored:7b", "llama3.1:latest"];
        populateModels(fallbacks, saved || fallbacks[0]);
      });
  });

  // Save on change
  modelSelect.addEventListener("change", (e) => {
    chrome.storage.local.set({ rewriteModel: e.target.value }, () => {
      console.log("[SecurePrompt] Selected rewrite model saved: " + e.target.value);
    });
  });
});

// SecurePrompt settings manager
document.addEventListener("DOMContentLoaded", () => {
  const modelSelect = document.getElementById("model-select");

  // Load existing configuration
  chrome.storage.local.get(["rewriteModel"], (result) => {
    if (result.rewriteModel) {
      modelSelect.value = result.rewriteModel;
    }
  });

  // Save on change
  modelSelect.addEventListener("change", (e) => {
    chrome.storage.local.set({ rewriteModel: e.target.value }, () => {
      console.log("Model setting saved: " + e.target.value);
    });
  });
});

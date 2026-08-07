(function() {
    // Intercept HTMLInputElement.click() for off-DOM file inputs
    const originalClick = HTMLInputElement.prototype.click;
    HTMLInputElement.prototype.click = function() {
        if (this.type === 'file') {
            this.addEventListener('change', (e) => {
                if (e.target.files && e.target.files.length > 0) {
                    window.postMessage({ type: 'SECURE_PROMPT_FILE_INJECTED', file: e.target.files[0] }, '*');
                }
            }, { once: true });
        }
        return originalClick.call(this);
    };

    // Intercept window.showOpenFilePicker
    if (window.showOpenFilePicker) {
        const origShowOpenFilePicker = window.showOpenFilePicker;
        window.showOpenFilePicker = async function(...args) {
            const handles = await origShowOpenFilePicker.apply(this, args);
            if (handles && handles.length > 0) {
                try {
                    const file = await handles[0].getFile();
                    window.postMessage({ type: 'SECURE_PROMPT_FILE_INJECTED', file: file }, '*');
                } catch (e) {}
            }
            return handles;
        };
    }
})();

// Regex rule editor: wires the vendored ACE editor to the rule content and the
// "Update rule" button. Designed for the app's strict CSP:
//   * ACE styles are linked as static stylesheets, so style injection is turned
//     off (useStrictCSP) and no inline <style> is ever created.
//   * The JSON worker is loaded from a same-origin URL, never a blob.
//   * No innerHTML is used anywhere here; content flows through textarea.value
//     and the ACE document model only.
(() => {
  "use strict";

  const host = document.querySelector("[data-ace-editor]");
  const source = document.getElementById("rule-source");
  if (!host || !source || typeof window.ace === "undefined") return;

  const mode = host.getAttribute("data-editor-mode") || "ace/mode/json";
  const updateUrl = host.getAttribute("data-update-url");
  const csrfToken = host.getAttribute("data-csrf-token") || "";
  const submit = document.querySelector("[data-regex-submit]");
  const status = document.querySelector("[data-regex-status]");
  const isJson = mode === "ace/mode/json";

  // CSP-critical configuration, set before the editor is created.
  window.ace.config.set("basePath", "/static/vendor/ace");
  window.ace.config.set("loadWorkerFromBlob", false);
  window.ace.config.set("useStrictCSP", true);

  const editor = window.ace.edit(host);
  editor.setTheme("ace/theme/clouds_midnight");
  editor.session.setMode(mode);
  editor.setOptions({
    showGutter: true,            // show gutter
    showLineNumbers: true,       // show line numbers
    displayIndentGuides: true,   // show indent guides
    highlightActiveLine: true,   // highlight active line
    highlightSelectedWord: true, // highlight selected word
    selectionStyle: "line",      // full line selection
    useSoftTabs: true,           // soft tabs keep auto-indent consistent
    tabSize: 2,
    showPrintMargin: false,
  });
  // Auto-indent new lines from the active mode.
  editor.getSession().setUseSoftTabs(true);

  // Enable the browser spell checker on ACE's hidden input element.
  try {
    const input = editor.textInput && editor.textInput.getElement
      ? editor.textInput.getElement()
      : host.querySelector("textarea");
    if (input) input.setAttribute("spellcheck", "true");
  } catch (_error) {
    /* spellcheck is best-effort; never block editing over it */
  }

  // Load the content via the textarea value (exact bytes, no markup execution)
  // and place the cursor at the start.
  editor.setValue(source.value, -1);
  editor.clearSelection();

  const showMessage = (message, ok) => {
    if (status) {
      status.hidden = false;
      status.textContent = message;
      status.className = `form-message ${ok ? "success" : "error"}`;
    }
    window.alert(message);
  };

  // A light client-side guard that mirrors the backend: an empty file is always
  // rejected, and JSON lists must parse. The backend remains authoritative.
  const validateLocally = (content) => {
    if (content.trim() === "") {
      return "The rule file cannot be empty.";
    }
    if (isJson) {
      try {
        JSON.parse(content);
      } catch (error) {
        return `The rule content is not valid JSON: ${error.message}.`;
      }
    }
    return null;
  };

  submit?.addEventListener("click", async () => {
    if (!updateUrl) return;
    const content = editor.getValue();
    const localError = validateLocally(content);
    if (localError) {
      showMessage(localError, false);
      return;
    }
    submit.disabled = true;
    try {
      const response = await fetch(updateUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ csrf_token: csrfToken, content }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        showMessage(payload.error || "error in WAF server", false);
        return;
      }
      const written = typeof payload.rules_written === "number" ? payload.rules_written : 0;
      showMessage(`The rule was updated successfully (${written} item(s) written).`, true);
    } catch (_error) {
      showMessage("error in WAF server", false);
    } finally {
      submit.disabled = false;
    }
  });
})();

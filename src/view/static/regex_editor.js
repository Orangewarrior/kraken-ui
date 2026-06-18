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
  if (!host || !source) return;

  const mode = host.getAttribute("data-editor-mode") || "ace/mode/json";
  const updateUrl = host.getAttribute("data-update-url");
  const csrfToken = host.getAttribute("data-csrf-token") || "";
  const submit = document.querySelector("[data-regex-submit]");
  const status = document.querySelector("[data-regex-status]");
  const isJson = mode === "ace/mode/json";
  let editor = null;

  const setStatus = (message, ok) => {
    if (!status) return;
    status.hidden = false;
    status.textContent = message;
    status.className = `form-message ${ok ? "success" : "error"}`;
  };

  const currentContent = () => editor ? editor.getValue() : source.value;

  if (typeof window.ace === "undefined") {
    host.hidden = true;
    setStatus("Syntax editor failed to load; using the textarea editor.", false);
  } else {
    try {
      // CSP-critical configuration, set before the editor is created.
      window.ace.config.set("basePath", "/static/vendor/ace");
      window.ace.config.set("loadWorkerFromBlob", false);
      window.ace.config.set("useStrictCSP", true);
      const aceDom = window.ace.require && window.ace.require("ace/lib/dom");
      if (aceDom) {
        aceDom.removeChildren = (element) => element.replaceChildren();
      }

      const initialContent = source.value;
      const aceSource = document.createElement("textarea");
      aceSource.value = initialContent;
      aceSource.hidden = true;
      aceSource.setAttribute("aria-hidden", "true");
      host.before(aceSource);
      host.remove();

      // ACE calls `innerHTML = ""` when initialized from a generic element,
      // which violates the app's Trusted Types CSP. Its textarea path avoids
      // that sink by replacing the textarea with a generated editor container.
      editor = window.ace.edit(aceSource);
      const editorHost = editor.container;
      editorHost.id = host.id;
      editorHost.className = host.className;
      editorHost.setAttribute("data-ace-editor", "");
      editorHost.setAttribute("data-editor-mode", mode);
      editorHost.setAttribute("data-update-url", updateUrl || "");
      editorHost.setAttribute("data-csrf-token", csrfToken);
      editor.setTheme("ace/theme/clouds_midnight");
      editor.session.setUseWorker(false);
      editor.session.setMode(mode);
      editor.session.setUseWorker(false);
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
      editor.clearSelection();
      if (editor.getValue() === initialContent) {
        source.hidden = true;
        source.setAttribute("aria-hidden", "true");
        window.requestAnimationFrame(() => {
          editor.resize();
          editor.renderer.updateFull();
        });
      } else {
        editor.destroy();
        editor.container.remove();
        editor = null;
        source.hidden = false;
        source.removeAttribute("aria-hidden");
        setStatus("Syntax editor did not load the rule content; using the textarea editor.", false);
      }
    } catch (_error) {
      if (editor) {
        editor.destroy();
        editor.container.remove();
      }
      editor = null;
      source.hidden = false;
      source.removeAttribute("aria-hidden");
      setStatus("Syntax editor failed to initialize; using the textarea editor.", false);
    }
  }

  const showMessage = (message, ok) => {
    setStatus(message, ok);
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
    const content = currentContent();
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

(() => {
  "use strict";

  const qs = (selector, root = document) => root.querySelector(selector);
  const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const setupNav = () => {
    const toggle = qs("[data-menu-toggle]");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const isOpen = document.body.classList.toggle("nav-open");
        toggle.setAttribute("aria-expanded", String(isOpen));
      });
    }

    qsa("[data-accordion]").forEach((button) => {
      const targetId = button.getAttribute("aria-controls");
      const submenu = targetId ? document.getElementById(targetId) : null;
      if (!submenu) return;

      button.addEventListener("click", () => {
        const expanded = button.getAttribute("aria-expanded") === "true";
        button.setAttribute("aria-expanded", String(!expanded));
        submenu.hidden = expanded;
      });
    });
  };

  const setupSourceUpdate = () => {
    const panel = qs("[data-update-panel]");
    if (!panel) return;
    const form = qs("[data-update-form]", panel);
    const consoleBox = qs("[data-update-console]", panel);
    const submit = qs("[data-update-submit]", panel);
    const standby = qs("[data-update-standby]", panel);
    const countdown = qs("[data-update-countdown]", panel);
    let redirectStarted = false;
    let secondsRemaining = 120;

    const render = (status) => {
      if (consoleBox && typeof status.log === "string") {
        consoleBox.value = status.log;
        consoleBox.scrollTop = consoleBox.scrollHeight;
      }
      if (submit) submit.disabled = Boolean(status.in_progress);
      if (status.phase === "restarting" && !redirectStarted) {
        redirectStarted = true;
        secondsRemaining = Number(status.redirect_after_seconds) || 120;
        if (standby) standby.hidden = false;
        if (countdown) countdown.textContent = String(secondsRemaining);
        window.setInterval(() => {
          secondsRemaining = Math.max(0, secondsRemaining - 1);
          if (countdown) countdown.textContent = String(secondsRemaining);
        }, 1000);
        window.setTimeout(() => {
          window.location.assign("/kraken_ui/login");
        }, secondsRemaining * 1000);
      }
    };

    const poll = async () => {
      try {
        const response = await fetch("/kraken_ui/auth/api/update_kraken_ui", {
          credentials: "same-origin",
          cache: "no-store"
        });
        if (response.ok) render(await response.json());
      } catch (_error) {
        if (redirectStarted && consoleBox && !consoleBox.value.includes("Waiting for the updated web UI")) {
          consoleBox.value += "\nWaiting for the updated web UI to accept connections...\n";
        }
      }
    };

    if (form) {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (submit) submit.disabled = true;
        if (consoleBox) consoleBox.value = "Starting update request...\n";
        try {
          const response = await fetch(form.action, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(new FormData(form))
          });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          render(await response.json());
        } catch (error) {
          if (consoleBox) consoleBox.value += `Unable to start update: ${error.message}\n`;
          if (submit) submit.disabled = false;
        }
      });
    }

    poll();
    window.setInterval(poll, 1000);
  };

  document.addEventListener("DOMContentLoaded", () => {
    setupNav();
    setupSourceUpdate();
  });
})();


/* KrakenWaf local table, password policy and evidence highlighter.
   No CDN, no NPM, no third-party runtime dependency. */
(() => {
  "use strict";

  const qs = (selector, root = document) => root.querySelector(selector);
  const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const debounce = (fn, delay = 220) => {
    let timer = 0;
    return (...args) => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => fn(...args), delay);
    };
  };

  const passwordScore = (password, username, email, optional) => {
    const value = password || "";
    if (optional && value.length === 0) {
      return { ok: true, label: "Strength: unchanged", rules: { length: true, lower: true, upper: true, digit: true, symbol: true, identity: true } };
    }

    const local = String(email || "").split("@")[0].toLowerCase();
    const lowered = value.toLowerCase();
    const identityTokens = [username, email, local].map((x) => String(x || "").trim().toLowerCase()).filter((x) => x.length >= 3);
    const rules = {
      length: value.length >= 14,
      lower: /[a-z]/.test(value),
      upper: /[A-Z]/.test(value),
      digit: /[0-9]/.test(value),
      symbol: /[^A-Za-z0-9]/.test(value),
      identity: !identityTokens.some((token) => lowered.includes(token))
    };
    const score = Object.values(rules).filter(Boolean).length;
    const characterClasses = [rules.lower, rules.upper, rules.digit, rules.symbol].filter(Boolean).length;
    return {
      ok: rules.length && rules.identity && characterClasses >= 3,
      label: score <= 2 ? "Strength: weak" : score <= 4 ? "Strength: medium" : score === 5 ? "Strength: almost strong" : "Strength: strong",
      rules
    };
  };

  const setupPasswordPolicies = () => {
    qsa("[data-password-policy]").forEach((form) => {
      const password = qs("[data-strong-password]", form);
      if (!password) return;
      const username = qs("#username", form);
      const email = qs("#email", form);
      const submit = qs("[data-policy-submit]", form);
      const strength = qs("[data-password-strength]", form);
      const rulesList = qs("[data-password-rules]", form);
      const optional = password.hasAttribute("data-optional-password");

      const update = () => {
        const result = passwordScore(password.value, username?.value, email?.value, optional);
        if (strength) strength.textContent = result.label;
        if (rulesList) {
          Object.entries(result.rules).forEach(([name, ok]) => {
            const item = qs(`[data-rule="${name}"]`, rulesList);
            if (item) item.classList.toggle("passed", ok);
          });
        }
        if (submit) submit.disabled = !result.ok;
        password.setAttribute("aria-invalid", String(!result.ok));
        return result.ok;
      };

      [password, username, email].forEach((field) => field?.addEventListener("input", update));
      form.addEventListener("submit", (event) => {
        if (!update()) {
          event.preventDefault();
          password.focus();
        }
      });
      update();
    });
  };

  const cell = (text, className) => {
    const td = document.createElement("td");
    if (className) td.className = className;
    td.textContent = text ?? "";
    return td;
  };

  const linkCell = (href, label, className, newTab = false) => {
    const td = document.createElement("td");
    const a = document.createElement("a");
    a.href = href || "#";
    a.className = className;
    a.textContent = label;
    if (newTab) {
      a.target = "_blank";
      a.rel = "noopener noreferrer";
    }
    td.appendChild(a);
    return td;
  };

  const badgeCell = (text) => {
    const td = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge-status ${String(text || "").toLowerCase()}`;
    badge.textContent = text || "unknown";
    td.appendChild(badge);
    return td;
  };

  const postActionCell = (action, fieldName, fieldValue, csrfToken, label, className, newTab, confirmDelete) => {
    const td = document.createElement("td");
    const form = document.createElement("form");
    form.method = "post";
    form.action = action;
    if (newTab) form.target = "_blank";
    if (confirmDelete) form.setAttribute("data-confirm-delete", "");

    const csrf = document.createElement("input");
    csrf.type = "hidden";
    csrf.name = "csrf_token";
    csrf.value = csrfToken || "";
    const identity = document.createElement("input");
    identity.type = "hidden";
    identity.name = fieldName;
    identity.value = String(fieldValue ?? "");
    const button = document.createElement("button");
    button.type = "submit";
    button.className = className;
    button.textContent = label;
    form.append(csrf, identity, button);
    td.append(form);
    return td;
  };

  const buildUserRow = (item, csrfToken) => {
    const tr = document.createElement("tr");
    tr.append(
      cell(item.id),
      cell(item.username),
      cell(item.email),
      badgeCell(item.user_type),
      badgeCell(item.status),
      badgeCell(item.mfa),
      cell(item.created_at),
      postActionCell("/kraken_ui/auth/edit_user", "id_user", item.id, csrfToken, "Edit", "table-icon edit-icon", true, false),
      postActionCell("/kraken_ui/auth/delete_user_action", "user_identity", item.id, csrfToken, "X", "table-icon delete-icon", false, true)
    );
    return tr;
  };

  // Keep wide columns compact: a value longer than `limit` chars is shown as
  // "..." plus its trailing `limit` chars (limit + 3 total). The tail is the
  // discriminating part — a URI's query string, a rule's specific token — so the
  // head is dropped. The full, untruncated value is always exposed on hover as a
  // title tooltip. Request URI is capped at 61 chars, Rule match at 13.
  const truncatedTailCell = (value, limit) => {
    const text = String(value ?? "");
    const td = document.createElement("td");
    td.textContent = text.length > limit ? `...${text.slice(text.length - limit)}` : text;
    if (text) td.title = text;
    return td;
  };

  const buildAttackRow = (item) => {
    const tr = document.createElement("tr");
    // Clicking the ID or the client IP opens the full WAF request in a new tab.
    const detailHref = `/kraken_ui/auth/view_waf_request/?id=${encodeURIComponent(item.id ?? "")}`;
    tr.append(
      linkCell(detailHref, String(item.id ?? ""), "table-link", true),
      badgeCell(item.severity),
      cell(item.title),
      linkCell(detailHref, String(item.client_ip ?? ""), "table-link", true),
      truncatedTailCell(item.request_uri, 61),
      truncatedTailCell(item.rule_match, 13),
      cell(item.occurred_at),
      cell(item.country)
    );
    return tr;
  };

  const buildRows = (kind, items, csrfToken) => items.map((item) => kind === "attacks" ? buildAttackRow(item) : buildUserRow(item, csrfToken));

  // Columns exported to CSV per table kind: [field, header]. Action columns
  // (edit/delete) are intentionally excluded; values are exported untruncated.
  const CSV_COLUMNS = {
    attacks: [
      ["id", "ID"], ["severity", "Severity"], ["title", "Title"], ["client_ip", "Client IP"],
      ["request_uri", "Request URI"], ["rule_match", "Rule match"], ["occurred_at", "Occurred at"], ["country", "Country"]
    ],
    users: [
      ["id", "ID"], ["username", "Username"], ["email", "Email"],
      ["user_type", "Type"], ["status", "Status"], ["mfa", "2MFA"], ["created_at", "Created"]
    ]
  };

  // RFC 4180: quote a field when it contains a comma, quote or newline, doubling
  // any embedded quotes.
  const csvEscape = (value) => {
    const text = String(value ?? "");
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };

  const toCsv = (columns, rows) => {
    const header = columns.map(([, label]) => csvEscape(label)).join(",");
    const lines = rows.map((item) => columns.map(([key]) => csvEscape(item[key])).join(","));
    return [header, ...lines].join("\r\n");
  };

  // Build the CSV client-side and hand it to the browser as a download. A leading
  // BOM keeps spreadsheets reading it as UTF-8. The anchor's `download` attribute
  // makes this a user-initiated download, not a fetch governed by the CSP.
  const downloadCsv = (filename, content) => {
    const blob = new Blob(["\ufeff" + content], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  const statusRow = (message) => {
    const row = document.createElement("tr");
    const statusCell = document.createElement("td");
    statusCell.colSpan = 9;
    statusCell.className = "muted-cell";
    statusCell.textContent = message;
    row.append(statusCell);
    return row;
  };

  const setupKwTables = () => {
    qsa("[data-kw-table]").forEach((table) => {
      const id = table.id;
      const tbody = qs("tbody", table);
      const kind = table.getAttribute("data-table-kind") || "users";
      const ajaxUrl = table.getAttribute("data-ajax-url");
      const csrfToken = table.getAttribute("data-csrf-token") || "";
      const serverSide = table.getAttribute("data-server-side") === "true";
      const pageSize = Number.parseInt(table.getAttribute("data-page-size") || "8", 10);
      const search = qs(`[data-kw-table-search="${id}"]`);
      const searchField = qs(`[data-kw-table-field="${id}"]`);
      const previous = qs(`[data-kw-table-prev="${id}"]`);
      const next = qs(`[data-kw-table-next="${id}"]`);
      const info = qs(`[data-kw-table-info="${id}"]`);
      let page = 1;
      let draw = 1;
      let cache = [];
      let total = 0;
      let filtered = 0;
      // Rows currently shown, kept so the CSV button can export the current page.
      let lastRows = [];
      // Which column the attacks table is ordered by and in which direction.
      // Severity descending is the historical default; clicking Occurred at
      // switches to that column starting newest-first (descending).
      let sortColumn = "severity";
      let sortOrder = "desc";

      const clientFilter = () => {
        const term = (search?.value || "").trim().toLowerCase();
        return term
          ? cache.filter((item) => Object.values(item).some((value) => String(value).toLowerCase().includes(term)))
          : cache;
      };

      const render = async () => {
        if (!tbody || !ajaxUrl) return;
        tbody.replaceChildren(statusRow("Loading..."));
        try {
          let rows;
          if (serverSide) {
            const url = new URL(ajaxUrl, window.location.origin);
            url.searchParams.set("draw", String(draw++));
            url.searchParams.set("start", String((page - 1) * pageSize));
            url.searchParams.set("length", String(pageSize));
            url.searchParams.set("search[value]", search?.value || "");
            if (kind === "attacks") {
              url.searchParams.set("search_field", searchField?.value || "all");
              url.searchParams.set("sort", sortColumn);
              url.searchParams.set("order", sortOrder);
            }
            const response = await fetch(url, { headers: { "Accept": "application/json" }, credentials: "same-origin" });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const payload = await response.json();
            rows = Array.isArray(payload.data) ? payload.data : [];
            total = Number(payload.recordsTotal || rows.length);
            filtered = Number(payload.recordsFiltered || rows.length);
          } else {
            if (cache.length === 0) {
              const response = await fetch(ajaxUrl, { headers: { "Accept": "application/json" }, credentials: "same-origin" });
              if (!response.ok) throw new Error(`HTTP ${response.status}`);
              const payload = await response.json();
              cache = Array.isArray(payload.data) ? payload.data : [];
              total = Number(payload.recordsTotal || cache.length);
            }
            const filteredRows = clientFilter();
            filtered = filteredRows.length;
            rows = filteredRows.slice((page - 1) * pageSize, page * pageSize);
          }

          const totalPages = Math.max(1, Math.ceil(filtered / pageSize));
          if (page > totalPages) { page = totalPages; return render(); }
          lastRows = rows;
          tbody.replaceChildren(...buildRows(kind, rows, csrfToken));
          setupDeleteConfirmations(tbody);
          if (info) info.textContent = `Page ${page} of ${totalPages} • ${filtered} filtered / ${total} total`;
          if (previous) previous.disabled = page <= 1;
          if (next) next.disabled = page >= totalPages;
        } catch (error) {
          tbody.replaceChildren(statusRow("Failed to load table data."));
          if (info) info.textContent = "Ajax error";
        }
      };

      previous?.addEventListener("click", () => { page = Math.max(1, page - 1); render(); });
      next?.addEventListener("click", () => { page += 1; render(); });
      search?.addEventListener("input", debounce(() => { page = 1; render(); }));
      searchField?.addEventListener("change", () => { page = 1; if (search?.value) render(); });

      // Export the current page of rows to a CSV download.
      const csvButton = qs(`[data-kw-table-csv="${id}"]`);
      const csvColumns = CSV_COLUMNS[kind];
      csvButton?.addEventListener("click", () => {
        if (!csvColumns || lastRows.length === 0) return;
        const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
        downloadCsv(`${kind}-page-${page}-${stamp}.csv`, toCsv(csvColumns, lastRows));
      });

      const severitySort = qs("[data-sort-severity]", table);
      const occurredSort = qs("[data-sort-occurred]", table);
      // Clicking a sortable header toggles direction when it is already the active
      // column, otherwise it switches to that column starting descending.
      const applySort = (column, header) => {
        if (sortColumn === column) {
          sortOrder = sortOrder === "desc" ? "asc" : "desc";
        } else {
          sortColumn = column;
          sortOrder = "desc";
        }
        [severitySort, occurredSort].forEach((element) => element?.removeAttribute("data-order"));
        header.setAttribute("data-order", sortOrder);
        page = 1;
        render();
      };
      severitySort?.addEventListener("click", () => applySort("severity", severitySort));
      occurredSort?.addEventListener("click", () => applySort("occurred_at", occurredSort));
      [severitySort, occurredSort].forEach((header) => {
        header?.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            header.click();
          }
        });
      });
      render();
    });
  };

  const setupDeleteConfirmations = (root = document) => {
    qsa("[data-confirm-delete]", root).forEach((form) => {
      if (form.getAttribute("data-confirm-ready") === "true") return;
      form.setAttribute("data-confirm-ready", "true");
      form.addEventListener("submit", (event) => {
        if (!window.confirm("Are you sure you want to delete this account?")) {
          event.preventDefault();
        }
      });
    });
  };

  const svgElement = (name, attributes = {}) => {
    const element = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
    return element;
  };

  const chartColors = ["#ff8a00", "#ffb020", "#36d66b", "#ef4444", "#991b1b", "#38bdf8", "#a78bfa", "#f472b6", "#facc15", "#94a3b8"];

  const drawPie = (root, legendRoot, values) => {
    if (!root || !legendRoot) return;
    const usable = values.filter((item) => Number(item.value) > 0);
    const total = usable.reduce((sum, item) => sum + Number(item.value), 0);
    if (total <= 0) {
      root.textContent = "No CMC detections in the database.";
      legendRoot.replaceChildren();
      return;
    }
    const svg = svgElement("svg", { viewBox: "0 0 240 240", role: "img", "aria-label": "CMC detections pie plot" });
    const radius = 82;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    usable.forEach((item, index) => {
      const fraction = Number(item.value) / total;
      const circle = svgElement("circle", {
        cx: 120, cy: 120, r: radius, fill: "none",
        stroke: chartColors[index % chartColors.length],
        "stroke-width": 38,
        "stroke-dasharray": `${fraction * circumference} ${circumference}`,
        "stroke-dashoffset": -offset,
        transform: "rotate(-90 120 120)"
      });
      offset += fraction * circumference;
      svg.append(circle);
    });
    const center = svgElement("text", { x: 120, y: 126, "text-anchor": "middle", class: "svg-total" });
    center.textContent = String(total);
    svg.append(center);
    root.replaceChildren(svg);
    legendRoot.replaceChildren(...usable.map((item, index) => {
      const row = document.createElement("span");
      row.className = "chart-legend-row";
      const marker = document.createElement("i");
      marker.className = `chart-color-${index % chartColors.length}`;
      const text = document.createElement("span");
      text.textContent = `${item.label}: ${item.value}`;
      row.append(marker, text);
      return row;
    }));
  };

  const drawBars = (root, values) => {
    if (!root) return;
    const usable = values.filter((item) => Number(item.value) > 0).slice(0, 12);
    if (usable.length === 0) {
      root.textContent = "Per-module metrics are unavailable.";
      return;
    }
    const width = 760;
    const rowHeight = 34;
    const height = usable.length * rowHeight + 24;
    const max = Math.max(...usable.map((item) => Number(item.value)), 1);
    const svg = svgElement("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Module blocks bar plot" });
    usable.forEach((item, index) => {
      const y = index * rowHeight + 8;
      const label = svgElement("text", { x: 4, y: y + 18, class: "svg-label" });
      label.textContent = `${item.engine}:${item.module}`;
      const barWidth = (Number(item.value) / max) * 400;
      const bar = svgElement("rect", { x: 280, y, width: barWidth, height: 22, rx: 5, fill: chartColors[index % chartColors.length] });
      const count = svgElement("text", { x: 292 + barWidth, y: y + 17, class: "svg-count" });
      count.textContent = String(item.value);
      svg.append(label, bar, count);
    });
    root.replaceChildren(svg);
  };

  const renderRank = (root, values) => {
    if (!root) return;
    if (!Array.isArray(values) || values.length === 0) {
      root.textContent = "No data.";
      return;
    }
    root.replaceChildren(...values.map((item, index) => {
      const row = document.createElement("div");
      row.className = "rank-row";
      const position = document.createElement("strong");
      position.textContent = String(index + 1);
      const label = document.createElement("span");
      label.textContent = item.label || "Unknown";
      const value = document.createElement("b");
      value.textContent = String(item.value);
      row.append(position, label, value);
      return row;
    }));
  };

  const setupDashboard = async () => {
    const metricsRoot = qs("[data-dashboard-metrics]");
    if (!metricsRoot) return;
    const errorRoot = qs("[data-dashboard-error]");
    try {
      const response = await fetch("/kraken_ui/auth/api/dashboard", {
        headers: { "Accept": "application/json" },
        credentials: "same-origin"
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const metrics = data.metrics || {};
      const fields = {
        requests_inspected: metrics.requests_inspected,
        requests_blocked: metrics.requests_blocked,
        rate_limit_hits: metrics.rate_limit_hits,
        average_latency: `${Number(data.average_latency_ms || 0).toFixed(2)} ms`,
        redis_failopen: metrics.redis_rate_limit_failopen,
        redis_failclosed: metrics.redis_rate_limit_failclosed,
        trace_forwarded: metrics.traceparent_forwarded,
        trace_generated: metrics.traceparent_generated
      };
      Object.entries(fields).forEach(([name, value]) => {
        const target = qs(`[data-metric="${name}"]`);
        if (target) target.textContent = typeof value === "number" ? value.toLocaleString("en-US") : String(value ?? 0);
      });
      if (errorRoot && (!data.metrics_available || !data.database_available)) {
        errorRoot.hidden = false;
        errorRoot.textContent = "Some observability data is unavailable. Check waf-endpoint, waf-cert-ca, BEARER_PASSWORD and db_local.";
      }
      drawPie(qs("[data-cmc-pie]"), qs("[data-cmc-legend]"), data.cmc_detections || []);
      drawBars(qs("[data-module-bars]"), data.module_blocks || []);
      renderRank(qs("[data-country-rank]"), data.countries || []);
      renderRank(qs("[data-ip-rank]"), data.client_ips || []);
    } catch (_error) {
      if (errorRoot) {
        errorRoot.hidden = false;
        errorRoot.textContent = "Unable to load the dashboard data.";
      }
    }
  };

  const highlightEvidence = () => {
    qsa("[data-evidence-code]").forEach((code) => {
      code.textContent = code.textContent || "";
    });
  };

  // CSP forbids inline scripts, external highlighters and innerHTML (Trusted
  // Types), so the WAF request payload is tokenised by building DOM nodes only.
  const appendText = (parent, text) => {
    if (text) parent.appendChild(document.createTextNode(text));
  };

  const appendToken = (parent, className, text) => {
    if (!text) return;
    const span = document.createElement("span");
    span.className = className;
    span.textContent = text;
    parent.appendChild(span);
  };

  const highlightBodyLine = (parent, line) => {
    const regex = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\b\d+(?:\.\d+)?\b)|(\btrue\b|\bfalse\b|\bnull\b)/g;
    let lastIndex = 0;
    let match;
    while ((match = regex.exec(line)) !== null) {
      appendText(parent, line.slice(lastIndex, match.index));
      if (match[1] && match[2]) {
        appendToken(parent, "waf-tok-json-key", match[1]);
        appendText(parent, match[2]);
      } else if (match[1]) {
        appendToken(parent, "waf-tok-string", match[1]);
      } else if (match[3]) {
        appendToken(parent, "waf-tok-number", match[3]);
      } else if (match[4]) {
        appendToken(parent, "waf-tok-keyword", match[4]);
      }
      lastIndex = regex.lastIndex;
    }
    appendText(parent, line.slice(lastIndex));
  };

  const highlightHttpLine = (parent, line, isFirst, inHeaders) => {
    const requestLine = /^([A-Z]{3,10})\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)\s*$/.exec(line);
    const statusLine = /^(HTTP\/\d(?:\.\d)?)\s+(\d{3})\s*(.*)$/.exec(line);
    if (isFirst && requestLine) {
      appendToken(parent, "waf-tok-method", requestLine[1]);
      appendText(parent, " ");
      appendToken(parent, "waf-tok-uri", requestLine[2]);
      appendText(parent, " ");
      appendToken(parent, "waf-tok-proto", requestLine[3]);
      return true;
    }
    if (isFirst && statusLine) {
      appendToken(parent, "waf-tok-proto", statusLine[1]);
      appendText(parent, " ");
      appendToken(parent, "waf-tok-status", statusLine[2]);
      if (statusLine[3]) {
        appendText(parent, " ");
        appendToken(parent, "waf-tok-status", statusLine[3]);
      }
      return true;
    }
    if (inHeaders && !isFirst) {
      const headerLine = /^([!#$%&'*+\-.^_`|~0-9A-Za-z]+):([\s\S]*)$/.exec(line);
      if (headerLine) {
        appendToken(parent, "waf-tok-header", headerLine[1]);
        appendText(parent, ":");
        appendToken(parent, "waf-tok-value", headerLine[2]);
        return true;
      }
    }
    highlightBodyLine(parent, line);
    return false;
  };

  const highlightWafPayload = () => {
    qsa("[data-waf-payload]").forEach((code) => {
      const source = code.textContent || "";
      if (!source) return;
      const lines = source.split("\n");
      code.textContent = "";
      let sawFirst = false;
      let inHeaders = true;
      lines.forEach((line, index) => {
        if (index > 0) appendText(code, "\n");
        const isBlank = line.trim() === "";
        if (!sawFirst && isBlank) {
          appendText(code, line);
          return;
        }
        if (inHeaders && isBlank && sawFirst) {
          inHeaders = false;
          appendText(code, line);
          return;
        }
        const isFirst = !sawFirst;
        sawFirst = true;
        inHeaders = highlightHttpLine(code, line, isFirst, inHeaders);
      });
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    setupPasswordPolicies();
    setupKwTables();
    setupDeleteConfirmations();
    setupDashboard();
    highlightEvidence();
    highlightWafPayload();
  });
})();

(() => {
  "use strict";

  const qs = (selector, root = document) => root.querySelector(selector);
  const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

  const pointString = (values, width = 320, height = 88, padding = 8) => {
    if (!Array.isArray(values) || values.length === 0) return "";
    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min || 1;
    return values.map((value, index) => {
      const x = padding + (index * (width - padding * 2)) / Math.max(values.length - 1, 1);
      const y = height - padding - ((value - min) * (height - padding * 2)) / range;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(" ");
  };

  const drawLineChart = (element, series) => {
    const width = 360;
    const height = element.classList.contains("mini-chart") ? 74 : 190;
    const datasets = Array.isArray(series[0]) ? series : [series];

    const polylines = datasets.map((values, index) => {
      const cssClass = index === 1 ? "chart-line success" : "chart-line";
      return `<polyline class="${cssClass}" points="${pointString(values, width, height)}"></polyline>`;
    }).join("");

    const fill = datasets[0] ? `<polyline class="chart-fill" points="${pointString(datasets[0], width, height)} ${width - 8},${height - 8} 8,${height - 8}"></polyline>` : "";

    element.innerHTML = `
      <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Traffic chart">
        ${fill}
        ${polylines}
      </svg>`;
  };

  const drawCharts = () => {
    qsa("[data-chart]").forEach((element) => {
      const key = element.getAttribute("data-chart");
      const datasets = {
        requests: [12, 16, 14, 20, 18, 25, 19, 30, 23, 26, 22, 34, 31, 40, 33, 42],
        blocked: [4, 8, 7, 10, 9, 12, 11, 18, 14, 15, 13, 21, 18, 23, 22, 27],
        allowed: [10, 12, 15, 14, 19, 17, 22, 21, 26, 24, 28, 27, 31, 30, 35, 33],
        errors: [2, 4, 3, 6, 5, 7, 4, 9, 8, 10, 6, 11, 8, 12, 9, 14],
        overview: [
          [18, 22, 19, 25, 24, 30, 28, 34, 31, 37, 33, 39, 36, 42, 38, 45, 41, 48],
          [11, 13, 12, 16, 15, 20, 18, 22, 21, 25, 23, 27, 25, 30, 29, 32, 31, 34]
        ]
      };

      drawLineChart(element, datasets[key] || datasets.requests);
    });
  };

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

  const setupBars = () => {
    qsa("[data-bar]").forEach((bar) => {
      const raw = Number.parseFloat(bar.getAttribute("data-bar") || "0");
      bar.style.width = `${clamp(raw, 0, 100)}%`;
    });
  };

  const setupHeartbeat = () => {
    const requests = qs("[data-live-requests]");
    const blocked = qs("[data-live-blocked]");
    const allowed = qs("[data-live-allowed]");
    const errorRate = qs("[data-live-error]");

    if (!requests || !blocked || !allowed || !errorRate) return;

    window.setInterval(() => {
      const req = 2600 + Math.floor(Math.random() * 620);
      const blk = 430 + Math.floor(Math.random() * 95);
      const alw = 18000 + Math.floor(Math.random() * 850);
      const err = (0.8 + Math.random() * 0.7).toFixed(2);

      requests.textContent = req.toLocaleString("en-US");
      blocked.textContent = blk.toLocaleString("en-US");
      allowed.textContent = alw.toLocaleString("en-US");
      errorRate.textContent = `${err}%`;
    }, 3500);
  };

  const buildRow = (item) => {
    const severity = String(item.severity || "").toLowerCase();
    const action = String(item.action || "").toLowerCase();

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(item.time)}</td>
      <td>${escapeHtml(item.method || "GET")}</td>
      <td>${escapeHtml(item.url || "/")}</td>
      <td>${escapeHtml(item.ip)}</td>
      <td>${escapeHtml(item.country)}</td>
      <td>${escapeHtml(item.status || "403")}</td>
      <td><span class="badge-status ${severity}">${escapeHtml(item.severity)}</span></td>
      <td class="${action === "allowed" ? "action-allowed" : "action-blocked"}">${escapeHtml(item.action)}</td>
    `;
    return tr;
  };

  const escapeHtml = (value) => String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

  const setupLocalPagination = async () => {
    const tableBody = qs("[data-json-table]");
    if (!tableBody) return;

    const source = tableBody.getAttribute("data-json-table");
    const pageSize = Number.parseInt(tableBody.getAttribute("data-page-size") || "6", 10);
    const pageInfo = qs("[data-page-info]");
    const previous = qs("[data-page-prev]");
    const next = qs("[data-page-next]");
    const searchInput = qs("[data-table-search]");

    let data = [];
    let filtered = [];
    let page = 1;

    try {
      const response = await fetch(source, {
        method: "GET",
        headers: { "Accept": "application/json" },
        credentials: "same-origin"
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      data = Array.isArray(payload.data) ? payload.data : [];
      filtered = data;
    } catch (_error) {
      data = [];
      filtered = [];
    }

    const render = () => {
      const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
      page = clamp(page, 1, totalPages);
      tableBody.replaceChildren(...filtered.slice((page - 1) * pageSize, page * pageSize).map(buildRow));

      if (pageInfo) pageInfo.textContent = `Page ${page} of ${totalPages} • ${filtered.length} records`;
      if (previous) previous.disabled = page <= 1;
      if (next) next.disabled = page >= totalPages;
    };

    const filter = () => {
      const term = (searchInput?.value || "").trim().toLowerCase();
      filtered = term
        ? data.filter((item) => Object.values(item).some((value) => String(value).toLowerCase().includes(term)))
        : data;
      page = 1;
      render();
    };

    previous?.addEventListener("click", () => { page -= 1; render(); });
    next?.addEventListener("click", () => { page += 1; render(); });
    searchInput?.addEventListener("input", filter);

    render();
  };

  document.addEventListener("DOMContentLoaded", () => {
    setupNav();
    setupBars();
    drawCharts();
    setupHeartbeat();
    setupLocalPagination();
  });
})();


/* KrakenWaf local table, password policy and evidence highlighter.
   No CDN, no NPM, no third-party runtime dependency. */
(() => {
  "use strict";

  const qs = (selector, root = document) => root.querySelector(selector);
  const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const escapeHtml = (value) => String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
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
    return {
      ok: score === 6,
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

  const buildUserRow = (item) => {
    const tr = document.createElement("tr");
    tr.append(
      cell(item.id),
      cell(item.username),
      cell(item.email),
      badgeCell(item.user_type),
      badgeCell(item.status),
      cell(item.created_at),
      linkCell(item.edit_url, "✎", "table-icon edit-icon", false),
      linkCell(item.delete_url, "×", "table-icon delete-icon", false)
    );
    return tr;
  };

  const buildAttackRow = (item) => {
    const tr = document.createElement("tr");
    tr.append(
      cell(item.id),
      cell(item.time),
      cell(item.ip),
      cell(item.method),
      cell(item.url),
      cell(item.rule),
      badgeCell(item.severity),
      cell(item.action, String(item.action).toLowerCase() === "allowed" ? "action-allowed" : "action-blocked"),
      linkCell(item.view_url, "⌕", "table-icon view-icon", true)
    );
    return tr;
  };

  const buildRows = (kind, items) => items.map((item) => kind === "attacks" ? buildAttackRow(item) : buildUserRow(item));

  const setupKwTables = () => {
    qsa("[data-kw-table]").forEach((table) => {
      const id = table.id;
      const tbody = qs("tbody", table);
      const kind = table.getAttribute("data-table-kind") || "users";
      const ajaxUrl = table.getAttribute("data-ajax-url");
      const serverSide = table.getAttribute("data-server-side") === "true";
      const pageSize = Number.parseInt(table.getAttribute("data-page-size") || "8", 10);
      const search = qs(`[data-kw-table-search="${id}"]`);
      const previous = qs(`[data-kw-table-prev="${id}"]`);
      const next = qs(`[data-kw-table-next="${id}"]`);
      const info = qs(`[data-kw-table-info="${id}"]`);
      let page = 1;
      let draw = 1;
      let cache = [];
      let total = 0;
      let filtered = 0;

      const clientFilter = () => {
        const term = (search?.value || "").trim().toLowerCase();
        return term
          ? cache.filter((item) => Object.values(item).some((value) => String(value).toLowerCase().includes(term)))
          : cache;
      };

      const render = async () => {
        if (!tbody || !ajaxUrl) return;
        tbody.innerHTML = `<tr><td colspan="9" class="muted-cell">Loading…</td></tr>`;
        try {
          let rows;
          if (serverSide) {
            const url = new URL(ajaxUrl, window.location.origin);
            url.searchParams.set("draw", String(draw++));
            url.searchParams.set("start", String((page - 1) * pageSize));
            url.searchParams.set("length", String(pageSize));
            url.searchParams.set("search[value]", search?.value || "");
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
          tbody.replaceChildren(...buildRows(kind, rows));
          if (info) info.textContent = `Page ${page} of ${totalPages} • ${filtered} filtered / ${total} total`;
          if (previous) previous.disabled = page <= 1;
          if (next) next.disabled = page >= totalPages;
        } catch (error) {
          tbody.innerHTML = `<tr><td colspan="9" class="muted-cell">Failed to load table data.</td></tr>`;
          if (info) info.textContent = "Ajax error";
        }
      };

      previous?.addEventListener("click", () => { page = Math.max(1, page - 1); render(); });
      next?.addEventListener("click", () => { page += 1; render(); });
      search?.addEventListener("input", debounce(() => { page = 1; render(); }));
      render();
    });
  };

  const highlightEvidence = () => {
    qsa("[data-evidence-code]").forEach((code) => {
      let html = escapeHtml(code.textContent || "");
      html = html
        .replace(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)(\s+[^\n]+)(\s+HTTP\/\d\.\d)/gm, '<span class="tok-method">$1</span>$2<span class="tok-proto">$3</span>')
        .replace(/^(HTTP\/\d\.\d\s+)(\d{3})([^\n]*)/gm, '<span class="tok-proto">$1</span><span class="tok-status">$2</span>$3')
        .replace(/^([A-Za-z0-9-]+)(:)/gm, '<span class="tok-header">$1</span>$2')
        .replace(/(&quot;[^&]*?&quot;)(\s*:)/g, '<span class="tok-json-key">$1</span>$2')
        .replace(/\b(blocked|true|false|null|high|medium|low|critical)\b/g, '<span class="tok-value">$1</span>');
      code.innerHTML = html;
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    setupPasswordPolicies();
    setupKwTables();
    highlightEvidence();
  });
})();

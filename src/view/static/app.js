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
    const svgNamespace = "http://www.w3.org/2000/svg";
    const width = 360;
    const height = element.classList.contains("mini-chart") ? 74 : 190;
    const datasets = Array.isArray(series[0]) ? series : [series];
    const svg = document.createElementNS(svgNamespace, "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Traffic chart");

    if (datasets[0]) {
      const fill = document.createElementNS(svgNamespace, "polyline");
      fill.setAttribute("class", "chart-fill");
      fill.setAttribute("points", `${pointString(datasets[0], width, height)} ${width - 8},${height - 8} 8,${height - 8}`);
      svg.append(fill);
    }

    datasets.forEach((values, index) => {
      const line = document.createElementNS(svgNamespace, "polyline");
      line.setAttribute("class", index === 1 ? "chart-line success" : "chart-line");
      line.setAttribute("points", pointString(values, width, height));
      svg.append(line);
    });
    element.replaceChildren(svg);
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
    const acceptedSeverities = new Set(["low", "medium", "high", "critical"]);
    const requestedSeverity = String(item.severity || "").toLowerCase();
    const severity = acceptedSeverities.has(requestedSeverity) ? requestedSeverity : "low";
    const action = String(item.action || "").toLowerCase();
    const tr = document.createElement("tr");
    [item.time, item.method || "GET", item.url || "/", item.ip, item.country, item.status || "403"]
      .forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = String(value ?? "");
        tr.append(cell);
      });
    const severityCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge-status ${severity}`;
    badge.textContent = String(item.severity ?? "");
    severityCell.append(badge);
    const actionCell = document.createElement("td");
    actionCell.className = action === "allowed" ? "action-allowed" : "action-blocked";
    actionCell.textContent = String(item.action ?? "");
    tr.append(severityCell, actionCell);
    return tr;
  };

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
      cell(item.created_at),
      postActionCell("/kraken_ui/auth/edit_user", "id_user", item.id, csrfToken, "Edit", "table-icon edit-icon", true, false),
      postActionCell("/kraken_ui/auth/delete_user_action", "user_identity", item.id, csrfToken, "X", "table-icon delete-icon", false, true)
    );
    return tr;
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
      cell(item.request_uri),
      cell(item.rule_match),
      cell(item.occurred_at),
      cell(item.country)
    );
    return tr;
  };

  const buildRows = (kind, items, csrfToken) => items.map((item) => kind === "attacks" ? buildAttackRow(item) : buildUserRow(item, csrfToken));

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
      const previous = qs(`[data-kw-table-prev="${id}"]`);
      const next = qs(`[data-kw-table-next="${id}"]`);
      const info = qs(`[data-kw-table-info="${id}"]`);
      let page = 1;
      let draw = 1;
      let cache = [];
      let total = 0;
      let filtered = 0;
      let severityOrder = "desc";

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
            if (kind === "attacks") url.searchParams.set("severity_order", severityOrder);
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
      const severitySort = qs("[data-sort-severity]", table);
      severitySort?.addEventListener("click", () => {
        severityOrder = severityOrder === "desc" ? "asc" : "desc";
        severitySort.setAttribute("data-order", severityOrder);
        page = 1;
        render();
      });
      severitySort?.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") severitySort.click();
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
        errorRoot.textContent = "Some observability data is unavailable. Check waf_endpoint, the certificate and db_local.";
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

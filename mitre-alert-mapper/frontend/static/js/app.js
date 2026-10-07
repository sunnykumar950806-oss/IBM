/* ── Shared utility / helper JS for MITRE ATT&CK Alert Mapper ──────────── */

// ── API helpers ─────────────────────────────────────────────────────────────
const API = {
  async get(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
    return r.json();
  },
  async post(url, body) {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
    return r.json();
  }
};

// ── Toast notifications ──────────────────────────────────────────────────────
function showToast(msg, type = "success", duration = 3500) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

// ── Confidence badge helper ──────────────────────────────────────────────────
function confidenceBadge(level) {
  if (!level) return '<span class="badge badge-low">—</span>';
  const map = { High: "badge-high", Medium: "badge-medium", Low: "badge-low" };
  return `<span class="badge ${map[level] || 'badge-low'}">${level}</span>`;
}

// ── Tactic badge ─────────────────────────────────────────────────────────────
function tacticBadge(name) {
  if (!name) return "";
  return `<span class="badge badge-tactic">${name}</span>`;
}

// ── Technique badge ──────────────────────────────────────────────────────────
function techBadge(id, name) {
  return `<span class="badge badge-tech" title="${name || ''}">${id}</span>`;
}

// ── Sigma badge ──────────────────────────────────────────────────────────────
function sigmaBadge(title) {
  return `<span class="badge badge-sigma">σ ${title}</span>`;
}

// ── Format ISO datetime to readable ─────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}

// ── Truncate string ──────────────────────────────────────────────────────────
function truncate(str, n = 80) {
  if (!str) return "—";
  return str.length > n ? str.slice(0, n) + "…" : str;
}

// ── Set active nav item ──────────────────────────────────────────────────────
function setActiveNav(page) {
  document.querySelectorAll(".nav-item").forEach(el => {
    el.classList.toggle("active", el.dataset.page === page);
  });
}

// ── Tabs ─────────────────────────────────────────────────────────────────────
function initTabs(containerSelector) {
  const container = document.querySelector(containerSelector);
  if (!container) return;
  const buttons = container.querySelectorAll(".tab-btn");
  const panels = container.querySelectorAll(".tab-panel");
  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      buttons.forEach(b => b.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const target = btn.dataset.tab;
      const panel = container.querySelector(`.tab-panel[data-tab="${target}"]`);
      if (panel) panel.classList.add("active");
    });
  });
  // Activate first tab
  if (buttons.length) buttons[0].click();
}

// ── Collapsible mapping panels ───────────────────────────────────────────────
function initMappingPanels() {
  document.querySelectorAll(".mapping-header").forEach(header => {
    header.addEventListener("click", () => {
      const body = header.nextElementSibling;
      body.classList.toggle("collapsed");
      const arrow = header.querySelector(".panel-arrow");
      if (arrow) arrow.textContent = body.classList.contains("collapsed") ? "▶" : "▼";
    });
  });
}

// ── Render bar chart (CSS-based) ─────────────────────────────────────────────
function renderBarChart(containerId, items, maxCount) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No data available yet.</p></div>';
    return;
  }
  const max = maxCount || Math.max(...items.map(i => i.count));
  container.innerHTML = items.map(item => `
    <div class="bar-row">
      <div class="bar-label" title="${item.name}">${item.name || item.id}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${max ? Math.round((item.count / max) * 100) : 0}%"></div>
      </div>
      <div class="bar-count">${item.count}</div>
    </div>
  `).join("");
}

// ── Render alert table row ───────────────────────────────────────────────────
function alertTableRow(alert) {
  return `
    <tr class="clickable" onclick="location.href='/alert/${alert.id}'">
      <td>#${alert.id}</td>
      <td>${alert.alert_type || "—"}</td>
      <td>${confidenceBadge(alert.top_confidence)}</td>
      <td>${alert.mapping_count}</td>
      <td>${alert.source_ip || "—"}</td>
      <td>${alert.username || "—"}</td>
      <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(alert.raw_input || '')}">${truncate(alert.raw_input, 60)}</td>
      <td>${fmtDate(alert.timestamp)}</td>
    </tr>`;
}

// ── HTML escape ──────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

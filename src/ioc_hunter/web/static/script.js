"use strict";

const $ = (sel) => document.querySelector(sel);
const create = (tag, props = {}, ...children) => {
  const el = document.createElement(tag);
  Object.assign(el, props);
  for (const c of children) {
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
};

const VERDICT_ORDER = { malicious: 3, suspicious: 2, benign: 1, unknown: 0 };
const STORAGE_KEY = "ioc-hunter-byok-keys";

const KEY_FIELDS = [
  { id: "key-abuse-ch", api: "abuse_ch_auth_key" },
  { id: "key-abuseipdb", api: "abuseipdb_api_key" },
  { id: "key-otx", api: "otx_api_key" },
  { id: "key-vt", api: "virustotal_api_key" },
];

async function fetchJson(url, opts = {}) {
  const resp = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const data = await resp.json().catch(() => ({}));
  return { ok: resp.ok, status: resp.status, data };
}

function showStatus(message, kind = "info") {
  const node = $("#status");
  node.textContent = message;
  node.className = `status ${kind}`;
}

function renderQuotaPill(quota, byokActive) {
  const pill = $("#quota-pill");
  if (!pill) return;
  if (byokActive) {
    pill.textContent = "BYOK • unlimited";
    pill.className = "quota-pill byok";
    return;
  }
  if (!quota) {
    pill.textContent = "…";
    pill.className = "quota-pill";
    return;
  }
  const { used, limit, remaining } = quota;
  pill.textContent = `${remaining}/${limit} demo scans left today`;
  pill.className = "quota-pill";
  if (remaining === 0) pill.classList.add("empty");
  else if (remaining <= Math.max(2, Math.floor(limit * 0.25))) pill.classList.add("low");
  pill.title = `Used ${used} of ${limit} today. Resets at UTC midnight.`;
}

function readKeys() {
  const keys = {};
  for (const { id, api } of KEY_FIELDS) {
    const el = document.getElementById(id);
    const v = el && el.value && el.value.trim();
    if (v) keys[api] = v;
  }
  return keys;
}

function applyKeysToInputs(keys) {
  for (const { id, api } of KEY_FIELDS) {
    const el = document.getElementById(id);
    if (el && keys[api]) el.value = keys[api];
  }
}

function loadRemembered() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function persistKeysIfChecked() {
  if (!$("#byok-remember").checked) return;
  const keys = readKeys();
  if (Object.keys(keys).length === 0) {
    localStorage.removeItem(STORAGE_KEY);
  } else {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
  }
}

function clearKeys() {
  for (const { id } of KEY_FIELDS) {
    const el = document.getElementById(id);
    if (el) el.value = "";
  }
  localStorage.removeItem(STORAGE_KEY);
  $("#byok-remember").checked = false;
}

function renderVerdict(v) {
  const klass = v.verdict;
  const card = create("div", { className: `verdict-card ${klass}` });

  const head = create("div", { className: "verdict-head" });
  const left = create("div");
  left.appendChild(create("span", { className: "verdict-ioc" }, v.ioc.value));
  left.appendChild(create("span", { className: "verdict-type" }, `· ${v.ioc.type}`));
  head.appendChild(left);

  const right = create("div");
  right.appendChild(create("span", { className: `badge ${klass}` }, klass.toUpperCase()));
  right.appendChild(
    create("span", { className: "verdict-meta" }, `  ${Math.round(v.confidence * 100)}%`)
  );
  head.appendChild(right);
  card.appendChild(head);

  if (v.tags && v.tags.length) {
    const tags = create("div", { className: "verdict-tags" });
    for (const t of v.tags.slice(0, 12)) {
      tags.appendChild(create("span", { className: "tag" }, t));
    }
    card.appendChild(tags);
  }

  if (v.results && v.results.length) {
    const sources = create("div", { className: "verdict-sources" });
    for (const r of v.results) {
      const chipClass = r.error ? "error" : r.verdict;
      const label = r.error ? `${r.source}` : `${r.source}: ${r.verdict}`;
      sources.appendChild(
        create("span", { className: `src-chip ${chipClass}`, title: r.error || "" }, label)
      );
    }
    card.appendChild(sources);
  }

  return card;
}

function clearResults() {
  $("#results").innerHTML = "";
}

async function loadSources() {
  const { ok, data } = await fetchJson("/api/sources");
  if (!ok) return;
  $("#version").textContent = `v${data.version}`;
  const grid = $("#sources-grid");
  grid.innerHTML = "";
  let active = 0;
  for (const s of data.sources) {
    if (s.active) active += 1;
    const pill = create("div", { className: "source-pill" });
    pill.appendChild(create("span", { className: "name" }, s.name));
    const dot = create("span", { className: `dot ${s.active ? "active" : ""}` });
    dot.title = s.active ? "active" : "key not configured";
    pill.appendChild(dot);
    grid.appendChild(pill);
  }
  $("#active-count").textContent = String(active);
}

async function loadQuota() {
  const { ok, data } = await fetchJson("/api/quota");
  if (ok) renderQuotaPill(data, false);
}

function highlightByokPanel() {
  const panel = $("#byok-panel");
  panel.open = true;
  panel.classList.add("urgent");
}

async function onScan() {
  const text = $("#input").value.trim();
  if (!text) {
    showStatus("paste something first", "error");
    return;
  }
  const btn = $("#scan-btn");
  btn.disabled = true;

  const keys = readKeys();
  const usingByok = Object.keys(keys).length > 0;
  showStatus(usingByok ? "scanning with your keys…" : "scanning…", "info");
  clearResults();

  try {
    const body = usingByok ? { text, keys } : { text };
    const { ok, status, data } = await fetchJson("/api/scan", {
      method: "POST",
      body: JSON.stringify(body),
    });

    if (status === 402) {
      renderQuotaPill(data.quota, false);
      showStatus(
        "daily demo quota used up — add your own API keys below to keep scanning",
        "error"
      );
      highlightByokPanel();
      return;
    }
    if (!ok) {
      showStatus(`error: ${data.detail || `HTTP ${status}`}`, "error");
      return;
    }

    renderQuotaPill(data.quota, data.byok);
    persistKeysIfChecked();

    if (!data.verdicts || data.verdicts.length === 0) {
      showStatus("no IOCs extracted from this input", "info");
      return;
    }
    const sorted = [...data.verdicts].sort(
      (a, b) =>
        (VERDICT_ORDER[b.verdict] ?? 0) - (VERDICT_ORDER[a.verdict] ?? 0) ||
        b.confidence - a.confidence
    );
    const container = $("#results");
    for (const v of sorted) container.appendChild(renderVerdict(v));
    const capped = data.iocs_extracted >= data.cap;
    const tail = capped ? ` · capped at ${data.cap}` : "";
    const mode = data.byok ? " · your keys" : "";
    showStatus(`${data.verdicts.length} IOC(s) checked${tail}${mode}`, "info");
  } catch (err) {
    showStatus(`error: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadSources();
  loadQuota();

  const remembered = loadRemembered();
  if (remembered) {
    applyKeysToInputs(remembered);
    $("#byok-remember").checked = true;
    // Auto-open the panel so the user can see their keys are loaded.
    $("#byok-panel").open = true;
  }

  $("#scan-btn").addEventListener("click", onScan);
  $("#byok-clear").addEventListener("click", clearKeys);
  $("#input").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      onScan();
    }
  });
});

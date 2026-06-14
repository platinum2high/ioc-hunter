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

async function fetchJson(url, opts = {}) {
  const resp = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const msg = data.detail || `HTTP ${resp.status}`;
    throw new Error(msg);
  }
  return data;
}

function showStatus(message, kind = "info") {
  const node = $("#status");
  node.textContent = message;
  node.className = `status ${kind}`;
}

function hideStatus() {
  $("#status").className = "status hidden";
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
  try {
    const data = await fetchJson("/api/sources");
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
  } catch (err) {
    console.warn("could not load sources:", err);
  }
}

async function onScan() {
  const text = $("#input").value.trim();
  if (!text) {
    showStatus("paste something first", "error");
    return;
  }
  const btn = $("#scan-btn");
  btn.disabled = true;
  showStatus("scanning…", "info");
  clearResults();
  try {
    const data = await fetchJson("/api/scan", {
      method: "POST",
      body: JSON.stringify({ text }),
    });
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
    showStatus(
      `${data.verdicts.length} IOC(s) checked${capped ? ` · capped at ${data.cap}` : ""}`,
      "info"
    );
  } catch (err) {
    showStatus(`error: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadSources();
  $("#scan-btn").addEventListener("click", onScan);
  $("#input").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      onScan();
    }
  });
});

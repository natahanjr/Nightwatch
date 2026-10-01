const $ = (s) => document.querySelector(s);

function banner(msg, kind) {
  let b = document.getElementById("global-banner");
  if (!b) {
    b = document.createElement("div");
    b.id = "global-banner";
    document.body.prepend(b);
  }
  b.className = "banner " + (kind || "info");
  b.textContent = msg;
}
window.addEventListener("error", (e) =>
  banner("Script error: " + (e.message || e.error), "err"));

if (location.protocol === "file:") {
  window.addEventListener("DOMContentLoaded", () =>
    banner("This console was opened from the file system. The analyzers need the " +
           "backend — open it through the server, e.g. http://127.0.0.1:8080/static/analyzer.html",
           "warn"));
}

const TITLES = {
  phish: ["Phishing", "Inspect links and email for deception."],
  traffic: ["Traffic", "Reconstruct sessions and surface scanning or C2."],
  honeypot: ["Honeypot", "Lure attackers and profile their behaviour."],
  logs: ["Logs", "Correlate signals and hunt for intrusions."],
};

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;
    if (!tab) return; // anchors (e.g. "Hero 3D") open a link, not a panel
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $("#tab-" + tab).classList.add("active");
    if (TITLES[tab]) {
      $("#page-title").textContent = TITLES[tab][0];
      $("#page-subtitle").textContent = TITLES[tab][1];
    }
  });
});

// Deep-link: activate a tab from the URL hash (e.g. /static/analyzer.html#honeypot)
function applyHashTab() {
  const name = (location.hash || "").replace("#", "");
  if (!name) return;
  const btn = document.querySelector('.tab[data-tab="' + name + '"]');
  if (btn) btn.click();
}
window.addEventListener("hashchange", applyHashTab);
applyHashTab();

async function api(path, options = {}) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function badge(verdict) {
  return `<span class="badge ${esc(verdict)}">${esc(verdict)}</span>`;
}

function scorebar(score) {
  const verdict = score >= 70 ? "phishing" : score >= 40 ? "suspicious" : "safe";
  return `<div class="scorebar"><div class="scorebar-fill ${verdict}"
    style="width:${Math.min(100, score)}%"></div></div>`;
}

function flagsList(flags) {
  if (!flags || !flags.length) return "";
  return `<div class="flags">${flags.map((f) => `<span class="flag">${esc(f)}</span>`).join("")}</div>`;
}

function findingsList(findings) {
  if (!findings || !findings.length) return "<p>No suspicious activity found.</p>";
  return `<ul class="findings">${findings.map((f) =>
    `<li><span class="sev ${esc(f.severity)}">[${esc(f.severity)}]</span> ${esc(f.label)} &mdash; ${f.count} event(s)<br><small>${esc(f.detail || f.sample || "")}</small></li>`
  ).join("")}</ul>`;
}

function verificationBlock(v) {
  if (!v) return "";
  let html = `<div class="card"><h3>Live verification</h3>`;
  if (v.error) html += `<div class="no">error: ${esc(v.error)}</div>`;
  if (v.resolves) html += `<div>Resolves to: <span class="mono">${esc(v.ips.join(", "))}</span></div>`;
  if (v.redirects && v.redirects.length) {
    html += `<div>Redirect chain:</div><ul class="list">${v.redirects.map((u) => `<li class="mono">${esc(u)}</li>`).join("")}</ul>`;
  }
  if (v.final_url) html += `<div>Final destination: <span class="mono">${esc(v.final_url)}</span></div>`;
  if (v.cross_domain_redirect) html += `<div class="no">WARNING: link redirects to a different domain</div>`;
  return html + `</div>`;
}

async function checkPhishUrl() {
  const url = $("#phish-url").value.trim();
  if (!url) return alert("Use a link to get a score and a live verification.");
  try {
    const r = await api("/api/phish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, verify: $("#phish-verify").checked }),
    });
    $("#phish-results").innerHTML = `
      <div class="result">
        <div class="result-card ${esc(r.verdict)}">
          <div class="result-top">
            <div class="result-url">${esc(r.url)}</div>
            ${badge(r.verdict)}
          </div>
          ${scorebar(r.score)}
          <div>Risk score: <strong>${r.score}/100</strong></div>
          ${flagsList(r.flags)}
        </div>
        ${verificationBlock(r.verification)}
      </div>`;
  } catch (e) { alert(e.message); }
}

async function checkPhishEmail() {
  const text = $("#phish-email").value;
  if (!text.trim()) return alert("Paste an email first.");
  try {
    const r = await api("/api/phish/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    let html = `<div class="result-card ${esc(r.overall_verdict)}">
        <div class="result-top">
          <div class="result-url">${r.urls_checked} link(s) found in email</div>
          ${badge(r.overall_verdict)}
        </div></div>`;
    r.results.forEach((u) => {
      html += `<div class="result-card ${esc(u.verdict)}">
        <div class="result-top">
          <div class="result-url">${esc(u.url)}</div>${badge(u.verdict)}
        </div>
        ${scorebar(u.score)}${flagsList(u.flags)}</div>`;
    });
    $("#phish-results").innerHTML = `<div class="result">${html}</div>`;
  } catch (e) { alert(e.message); }
}

async function analyzePcap() {
  const file = $("#pcap-file").files[0];
  if (!file) return alert("Choose a .pcap file first.");
  try {
    const r = await api("/api/pcap", { method: "POST", body: file });
    const proto = Object.entries(r.protocols)
      .map(([k, v]) => `${k}: ${v}`).join(" | ");
    const websites = r.http_hosts && r.http_hosts.length
      ? `<div class="card"><h3>Websites visited</h3><ul class="list">${
          r.http_hosts.map(([h, n]) => `<li><span class="mono">${esc(h)}</span> &mdash; ${n} request(s)</li>`).join("")
        }</ul></div>` : "";
    const dns = r.dns_queries && r.dns_queries.length
      ? `<div class="card"><h3>DNS queries</h3><ul class="list">${
          r.dns_queries.map(([d, n]) => `<li><span class="mono">${esc(d)}</span> &mdash; ${n}</li>`).join("")
        }</ul></div>` : "";
    const beacons = r.beacons && r.beacons.length
      ? `<div class="card"><h3>Possible beacons</h3><ul class="list">${
          r.beacons.map((b) => `<li class="no"><span class="mono">${esc(b.src)}</span> &rarr; <span class="mono">${esc(b.dst)}:${b.port}</span> every ~${b.interval}s (${b.count} packets)</li>`).join("")
        }</ul></div>` : "";
    $("#pcap-results").innerHTML = `
      <div class="result">
        <div class="stat-grid">
          <div class="stat"><div class="num">${r.packets_total}</div><div class="lbl">Packets</div></div>
          <div class="stat"><div class="num">${r.unique_connections}</div><div class="lbl">Connections</div></div>
          <div class="stat"><div class="num">${r.completed_connections}</div><div class="lbl">Established</div></div>
          <div class="stat"><div class="num">${r.http_requests}</div><div class="lbl">HTTP requests</div></div>
        </div>
        <div class="card"><h3>Protocols</h3><div>${esc(proto)}</div></div>
        <div class="card"><h3>Top sources</h3><ul class="list">${
          r.top_sources.map(([ip, n]) => `<li><span class="td mono">${esc(ip)}</span> &mdash; ${n} packets</li>`).join("")
        }</ul></div>
        <div class="card"><h3>Top destination ports</h3><ul class="list">${
          r.top_destination_ports.map(([p, n]) => `<li><span class="mono">${esc(p)}</span> &mdash; ${n} packets</li>`).join("")
        }</ul></div>
        ${websites}${dns}${beacons}
        <div class="card"><h3>Findings</h3>${findingsList(r.findings)}</div>
      </div>`;
  } catch (e) { alert(e.message); }
}

function hpEventRow(e) {
  const time = new Date(e.timestamp * 1000).toLocaleTimeString();
  if (e.event === "connection") {
    return `<tr><td>${esc(time)}</td><td class="mono">${esc(e.src_ip)}</td>
      <td class="mono">${esc(e.payload || "(no data)")}</td><td>&mdash;</td></tr>`;
  }
  return `<tr><td>${esc(time)}</td><td class="mono">${esc(e.src_ip)}</td>
    <td class="mono">${esc(e.method || "")} ${esc(e.path || "")}</td>
    <td class="${e.suspicious_path ? "no" : "ok"}">${e.suspicious_path ? "YES" : "no"}</td></tr>`;
}

function refreshHoneypot() {
  api("/api/honeypot/events").then((r) => {
    $("#hp-events tbody").innerHTML =
      r.events.filter((e) => e.event !== "server_start" && e.event !== "server_stop")
        .map(hpEventRow).join("") || '<tr><td colspan="4">No connections yet.</td></tr>';
  }).catch(() => {});
}

async function honeypotStart() {
  try {
    const r = await api("/api/honeypot/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: $("#hp-mode").value,
        port: parseInt($("#hp-port").value, 10),
      }),
    });
    updateHoneypotStatus(r);
  } catch (e) { alert(e.message); }
}

async function honeypotStop() {
  try { updateHoneypotStatus(await api("/api/honeypot/stop", { method: "POST" })); }
  catch (e) { alert(e.message); }
}

async function honeypotClear() {
  try { await api("/api/honeypot/clear", { method: "POST" }); refreshHoneypot(); }
  catch (e) { alert(e.message); }
}

function updateHoneypotStatus(s) {
  const pill = $("#hp-status");
  const txt = pill.querySelector(".status-text");
  $("#hp-start").disabled = s.running;
  $("#hp-stop").disabled = !s.running;
  if (s.running) {
    pill.className = "status inline run";
    txt.textContent = `Running: ${s.mode}://${s.host}:${s.port}`;
  } else {
    pill.className = "status inline";
    txt.textContent = "Honeypot is not running";
  }
}

async function honeypotAnalyze() {
  try {
    const r = await api("/api/honeypot/analysis");
    let html = `<div class="card"><h3>Attacker analysis</h3>
      <div>Events: ${r.total_events} &mdash; Attacker IPs: ${r.attacker_ips}</div>
      <ul class="list">${r.profiles.map((p) =>
        `<li><span class="mono">${esc(p.src_ip)}</span>: ${p.total_events} event(s),
          ${p.suspicious_path_hits} suspicious path hit(s)</li>`).join("")}</ul>
      <div style="margin-top:10px">${findingsList(r.findings)}</div></div>`;
    $("#hp-analysis").innerHTML = html;
  } catch (e) { alert(e.message); }
}

async function analyzeLogs() {
  const file = $("#log-file").files[0];
  if (!file) return alert("Choose a log file first.");
  try {
    const r = await api("/api/logs?name=" + encodeURIComponent(file.name), {
      method: "POST",
      body: file,
    });
    const a = r.analysis;
    const levels = Object.entries(a.levels)
      .map(([k, v]) => `${k}: ${v}`).join(" | ") || "none";
    $("#log-results").innerHTML = `
      <div class="result">
        <div class="stat-grid">
          <div class="stat"><div class="num">${a.events_total}</div><div class="lbl">Events</div></div>
          <div class="stat"><div class="num">${a.findings.length}</div><div class="lbl">Findings</div></div>
          <div class="stat"><div class="num">${a.bursts.length}</div><div class="lbl">Bursts</div></div>
        </div>
        <div class="card"><h3>Findings</h3>${findingsList(a.findings)}</div>
        <div class="row">
          <button class="btn primary" onclick="downloadReport()">Download report (.md)</button>
        </div>
      </div>`;
    window.__lastReport = r.report;
  } catch (e) { alert(e.message); }
}

function downloadReport() {
  const text = window.__lastReport;
  if (!text) return alert("Analyze a log file first.");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
  a.download = "nightwatch_report.md";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function refreshStatus() {
  try {
    const s = await api("/api/status");
    const el = $("#server-status");
    el.className = "status ok";
    el.querySelector(".status-text").textContent = `v${s.version} \u00b7 online`;
    const v = $("#app-version");
    if (v) v.textContent = s.version;
    updateHoneypotStatus(s.honeypot);
  } catch (e) {
    const el = $("#server-status");
    el.className = "status bad";
    el.querySelector(".status-text").textContent = "offline";
    banner("Cannot reach the dashboard API (/api/status). Open this page through " +
           "http://127.0.0.1:8080/static/analyzer.html while the server is running.", "warn");
  }
}

refreshStatus();
setInterval(refreshStatus, 3000);
setInterval(refreshHoneypot, 2000);

// ---- Module analyzers (M-05 .. M-10) ------------------------------------
function el(id) { return document.getElementById(id); }

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function showJson(divId, data) {
  const box = el(divId);
  box.innerHTML =
    '<div class="result-card"><pre class="mono" style="white-space:pre-wrap">' +
    escapeHtml(JSON.stringify(data, null, 2)) + "</pre></div>";
}

function showError(divId, msg) {
  el(divId).innerHTML =
    '<div class="result-card"><span class="badge error">' + escapeHtml(msg) + "</span></div>";
}

async function postJson(path, obj) {
  let res;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(obj),
    });
  } catch (e) {
    throw new Error("Cannot reach " + path + " — is the dashboard server running at " +
                    "http://127.0.0.1:8080? (" + e.message + ")");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function postFile(path, file) {
  const qs = file && file.name ? "?name=" + encodeURIComponent(file.name) : "";
  let res;
  try {
    res = await fetch(path + qs, { method: "POST", body: file });
  } catch (e) {
    throw new Error("Cannot reach " + path + " — is the dashboard server running at " +
                    "http://127.0.0.1:8080? (" + e.message + ")");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function withError(divId, fn) {
  const box = el(divId);
  if (box) box.innerHTML = '<div class="result-card"><span class="badge">working…</span></div>';
  fn().then((d) => showJson(divId, d)).catch((e) => showError(divId, e.message));
}

function analyzeThreatIntel() {
  const v = el("ti-value").value.trim();
  if (!v) return;
  withError("ti-results", () => postJson("/api/threat_intel", { value: v }));
}
function analyzeDfir() {
  const f = el("dfir-file").files[0];
  if (!f) return;
  withError("dfir-results", () => postFile("/api/dfir", f));
}
function analyzeSandbox() {
  const f = el("sb-file").files[0];
  if (!f) return;
  withError("sb-results", () => postFile("/api/sandbox", f));
}
function analyzeOsint() {
  const v = el("os-domain").value.trim();
  if (!v) return;
  withError("os-results", () => postJson("/api/osint", { domain: v }));
}
function analyzePosture() {
  const f = el("po-file").files[0];
  if (!f) return;
  withError("po-results", () => postFile("/api/posture", f));
}
function analyzeCryptoCert() {
  const v = el("cr-host").value.trim();
  if (!v) return;
  withError("cr-results", () => postJson("/api/crypto", { host: v }));
}
function analyzeCryptoText() {
  const v = el("cr-text").value;
  withError("cr-results", () => postJson("/api/crypto", { text: v }));
}

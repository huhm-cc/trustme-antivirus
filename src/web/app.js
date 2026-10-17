/* TrustmeAntivirus 前端邏輯 */

let api = null;
let lastLogIndex = 0;
let pollTimer = null;

/* ---------- 初始化 ---------- */
window.addEventListener("pywebviewready", init);

async function init() {
  api = window.pywebview.api;

  bindNavigation();
  bindScanControls();
  bindSettings();
  bindTheme();

  await loadSettings();
  await loadDashboard();
  await loadQuarantine();
  await loadHistory();

  startPolling();
  logLine("TrustmeAntivirus 前端已就緒。", "info");
}

/* ---------- 導航 ---------- */
function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`page-${btn.dataset.page}`).classList.add("active");

      if (btn.dataset.page === "dashboard") loadDashboard();
      if (btn.dataset.page === "quarantine") loadQuarantine();
      if (btn.dataset.page === "history") loadHistory();
    });
  });
}

/* ---------- 掃描控制 ---------- */
function bindScanControls() {
  document.getElementById("browse-btn").addEventListener("click", async () => {
    const result = await api.select_folder();
    if (result.ok) {
      document.getElementById("folder-input").value = result.path;
    }
  });

  document.getElementById("start-btn").addEventListener("click", async () => {
    const folder = document.getElementById("folder-input").value.trim();
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const result = await api.start_scan(folder, mode);
    if (!result.ok) showToast(result.error || "無法開始掃描", "risk");
  });

  document.getElementById("stop-btn").addEventListener("click", async () => {
    await api.stop_scan();
  });

  document.getElementById("export-csv-btn").addEventListener("click", async () => {
    const result = await api.export_csv();
    if (result.ok) showToast(`CSV 已匯出：${result.path}`, "safe");
    else showToast(result.error || "匯出失敗", "risk");
  });
}

/* ---------- 狀態輪詢 ---------- */
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(poll, 500);
  poll();
}

async function poll() {
  if (!api) return;

  const status = await api.get_status();
  updateStatusUI(status);

  const log = await api.get_log(lastLogIndex);
  for (const line of log.lines) {
    logLine(line.text, line.level);
    lastLogIndex = line.index;
  }

  for (const n of status.notifications) {
    showToast(n.text, n.kind);
  }
}

function updateStatusUI(s) {
  // 徽章
  const badge = document.getElementById("status-badge");
  if (s.is_scanning) {
    badge.textContent = "● 掃描中";
    badge.className = "badge scanning";
  } else if (s.risks > 0) {
    badge.textContent = "● 發現風險";
    badge.className = "badge risk";
  } else {
    badge.textContent = "● 就緒";
    badge.className = "badge idle";
  }

  // 按鈕狀態
  document.getElementById("start-btn").disabled = s.is_scanning;
  document.getElementById("stop-btn").disabled = !s.is_scanning;

  // 進度條
  const pct = Math.round(s.progress * 100);
  document.getElementById("progress-fill").style.width = `${pct}%`;
  document.getElementById("progress-text").textContent = s.is_scanning
    ? `掃描中 ${s.scanned}/${s.total}（${pct}%）`
    : (s.last_scan_finished_at ? `上次掃描完成於 ${s.last_scan_finished_at}` : "準備就緒");

  // 統計
  document.getElementById("s-scanned").textContent = s.scanned;
  document.getElementById("s-safe").textContent = s.safe;
  document.getElementById("s-risks").textContent = s.risks;
  document.getElementById("s-errors").textContent = s.errors;

  // 儀表板
  document.getElementById("d-total").textContent = s.total;
  document.getElementById("d-risks").textContent = s.risks;
  document.getElementById("d-safe").textContent = s.safe;

  // 防護狀態
  document.getElementById("p-lastscan").textContent = s.last_scan_finished_at || "尚未掃描";

  if (s.last_scan_finished_at) {
    const p = document.getElementById("p-lastscan");
    p.className = "on";
  }
}

/* ---------- 日誌 ---------- */
function logLine(text, level) {
  const box = document.getElementById("scan-log");
  const div = document.createElement("div");
  div.className = `log-line ${level}`;
  div.textContent = text;
  box.appendChild(div);
  if (box.children.length > 2000) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

/* ---------- 儀表板 ---------- */
async function loadDashboard() {
  if (!api) return;
  const info = await api.get_system_info();
  const table = document.getElementById("sysinfo-table");
  table.innerHTML = `
    <tr><td>作業系統</td><td>${info.os}</td></tr>
    <tr><td>CPU</td><td>${info.cpu_name}（${info.cpu_count} 核心）</td></tr>
    <tr><td>記憶體</td><td>${info.ram_total_gb} GB（使用率 ${info.ram_usage_percent}%）</td></tr>
    <tr><td>Python</td><td>${info.python}</td></tr>
  `;

  const status = await api.get_status();
  document.getElementById("ver-label").textContent = `v${status.version}`;
  document.getElementById("p-blacklist").className = "on";
  document.getElementById("p-blacklist").textContent = "啟用";
}

/* ---------- 隔離區 ---------- */
async function loadQuarantine() {
  if (!api) return;
  const data = await api.get_quarantine();
  const tbody = document.querySelector("#quarantine-table tbody");
  const count = document.getElementById("quarantine-count");
  count.textContent = data.items.length;
  count.className = data.items.length > 0 ? "pill" : "pill zero";
  document.getElementById("d-quarantined").textContent = data.items.length;

  tbody.innerHTML = data.items.length === 0
    ? `<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">目前沒有隔離檔案</td></tr>`
    : data.items.map((e) => `
      <tr>
        <td>${e.quarantined_name}</td>
        <td>${e.original_path}</td>
        <td>${e.quarantined_at}</td>
        <td>
          <button class="btn small" onclick="restoreFile('${e.quarantined_name}')">還原</button>
          <button class="btn small danger" onclick="deleteFile('${e.quarantined_name}')">永久刪除</button>
        </td>
      </tr>`).join("");
}

async function restoreFile(name) {
  const result = await api.restore_quarantined(name);
  showToast(result.ok ? "檔案已還原" : `還原失敗：${result.error}`, result.ok ? "safe" : "risk");
  loadQuarantine();
}

async function deleteFile(name) {
  if (!confirm("確定要永久刪除這個檔案嗎？此操作無法復原。")) return;
  const result = await api.delete_quarantined(name);
  showToast(result.ok ? "檔案已永久刪除" : `刪除失敗：${result.error}`, result.ok ? "safe" : "risk");
  loadQuarantine();
}

/* ---------- 歷史 ---------- */
async function loadHistory() {
  if (!api) return;
  const data = await api.get_history();
  const tbody = document.querySelector("#history-table tbody");
  tbody.innerHTML = data.items.length === 0
    ? `<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">尚無掃描記錄</td></tr>`
    : data.items.map((h) => `
      <tr>
        <td>${h.finished_at || h.started_at}</td>
        <td>${h.target_folder}</td>
        <td>${h.mode === "quick" ? "快速" : "完整"}</td>
        <td>${h.scanned_files}/${h.total_files}</td>
        <td class="${h.risk_files > 0 ? "red" : "green"}">${h.risk_files}</td>
        <td>${h.duration_seconds}s</td>
      </tr>`).join("");
}

/* ---------- 設定 ---------- */
function bindSettings() {
  document.getElementById("save-settings-btn").addEventListener("click", async () => {
    const enabled = document.getElementById("auto-check-toggle").checked;
    const interval = parseInt(document.getElementById("auto-interval").value, 10) || 60;
    const exts = document.getElementById("exclude-exts").value;
    const theme = document.getElementById("theme-select").value;

    const result = await api.save_settings(enabled, interval, exts, theme);
    if (result.ok) {
      showToast("設定已儲存 ✅", "safe");
      applyTheme(theme);
      updateProtectionStatus();
    } else {
      showToast(result.error || "儲存失敗", "risk");
    }
  });
}

async function loadSettings() {
  if (!api) return;
  const s = await api.get_settings();
  document.getElementById("auto-check-toggle").checked = !!s.auto_check_enabled;
  document.getElementById("auto-interval").value = s.auto_check_interval_min || 60;
  document.getElementById("exclude-exts").value = (s.exclude_exts || []).join(", ");
  document.getElementById("theme-select").value = s.theme || "dark";
  if (s.last_folder) document.getElementById("folder-input").value = s.last_folder;
  applyTheme(s.theme || "dark");
  updateProtectionStatus();
}

function updateProtectionStatus() {
  const enabled = document.getElementById("auto-check-toggle").checked;
  const el = document.getElementById("p-auto");
  el.textContent = enabled ? "啟用" : "停用";
  el.className = enabled ? "on" : "off";
}

/* ---------- 主題 ---------- */
function bindTheme() {
  document.getElementById("theme-btn").addEventListener("click", () => {
    const current = document.body.dataset.theme;
    const next = current === "dark" ? "light" : "dark";
    applyTheme(next);
    document.getElementById("theme-select").value = next;
  });
}

function applyTheme(theme) {
  document.body.dataset.theme = theme;
  document.getElementById("theme-btn").textContent = theme === "dark" ? "🌙" : "☀️";
}

/* ---------- Toast ---------- */
function showToast(text, kind = "info") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast ${kind}`;
  toast.textContent = text;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("out");
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
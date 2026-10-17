/* TrustmeAntivirus 前端邏輯 */

let api = null;
let lastLogIndex = 0;

/* ---------- 初始化 ---------- */
window.addEventListener("pywebviewready", init);

async function init() {
  api = window.pywebview.api;

  bindNavigation();
  bindScanControls();
  bindSettings();

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
let isScanningNow = false;

function startPolling() {
  poll();
}

async function poll() {
  if (!api) return;

  const status = await api.get_status();
  isScanningNow = status.is_scanning;
  updateStatusUI(status);

  const log = await api.get_log(lastLogIndex);
  if (log.lines.length > 0) {
    appendLogs(log.lines);
    lastLogIndex = log.lines[log.lines.length - 1].index;
  }

  for (const n of status.notifications) {
    showToast(n.text, n.kind);
  }

  // 動態輪詢：掃描中 500ms，閒置 1500ms（降低 CPU 佔用）
  setTimeout(poll, status.is_scanning ? 500 : 1500);
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

  const currentFile = s.current_file ? s.current_file.split(/[\\/]/).pop() : "";
  document.getElementById("progress-text").textContent = s.is_scanning
    ? `掃描中 ${s.scanned}/${s.total}（${pct}%）${currentFile ? " — " + currentFile : ""}`
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
  appendLogs([{ text, level }]);
}

function appendLogs(lines) {
  const box = document.getElementById("scan-log");
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    const div = document.createElement("div");
    div.className = `log-line ${line.level}`;
    div.textContent = line.text;
    frag.appendChild(div);
  }
  box.appendChild(frag);          // 批次插入，只觸發一次重排
  while (box.children.length > 1500) box.removeChild(box.firstChild);
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

  // VirusTotal / NVIDIA 啟用狀態
  const vtEl = document.getElementById("p-vt");
  vtEl.textContent = status.vt_enabled ? "啟用" : "未設定";
  vtEl.className = status.vt_enabled ? "on" : "off";

  const nvEl = document.getElementById("p-nvidia");
  nvEl.textContent = status.nvidia_enabled ? "啟用" : "未設定";
  nvEl.className = status.nvidia_enabled ? "on" : "off";

  // 自動背景檢查狀態
  const autoEl = document.getElementById("p-auto");
  const s = await api.get_settings();
  autoEl.textContent = s.auto_check_enabled ? `啟用（每 ${s.auto_check_interval_min} 分鐘）` : "停用";
  autoEl.className = s.auto_check_enabled ? "on" : "off";
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

    const result = await api.save_settings(enabled, interval, exts);
    if (result.ok) {
      showToast("設定已儲存 ✅", "safe");
      updateProtectionStatus();
    } else {
      showToast(result.error || "儲存失敗", "risk");
    }
  });

  bindApiKeyControls();
}

function bindApiKeyControls() {
  // 顯示 / 隱藏切換
  for (const [inputId, toggleId] of [["vt-key-input", "vt-key-toggle"],
                                     ["nv-key-input", "nv-key-toggle"]]) {
    document.getElementById(toggleId).addEventListener("click", () => {
      const el = document.getElementById(inputId);
      el.type = el.type === "password" ? "text" : "password";
    });
  }

  // 儲存金鑰
  document.getElementById("save-keys-btn").addEventListener("click", async () => {
    const vt = document.getElementById("vt-key-input").value;
    const nv = document.getElementById("nv-key-input").value;
    const result = await api.set_api_keys(vt, nv);
    if (result.ok) {
      showToast("API 金鑰已儲存 ✅", "safe");
      await loadApiKeyStatus();
      await loadDashboard();
    } else {
      showToast(result.error || "儲存失敗", "risk");
    }
  });

  // 開啟 Windows 環境變數設定視窗
  document.getElementById("open-env-btn").addEventListener("click", async () => {
    const result = await api.open_env_window();
    if (result.ok) {
      showToast("已開啟系統環境變數設定視窗", "info");
    } else {
      showToast(result.error || "開啟失敗", "risk");
    }
  });
}

async function loadApiKeyStatus() {
  const keys = await api.get_api_keys();
  const vtStatus = document.getElementById("vt-key-status");
  const nvStatus = document.getElementById("nv-key-status");

  vtStatus.textContent = keys.vt_set
    ? keys.vt_masked + (keys.vt_from_env ? "（來自環境變數）" : "")
    : "未設定";
  nvStatus.textContent = keys.nvidia_set
    ? keys.nvidia_masked + (keys.nvidia_from_env ? "（來自環境變數）" : "")
    : "未設定（模型：nemotron-3.5-lightning-30b-a3b）";
}

async function loadSettings() {
  if (!api) return;
  const s = await api.get_settings();
  document.getElementById("auto-check-toggle").checked = !!s.auto_check_enabled;
  document.getElementById("auto-interval").value = s.auto_check_interval_min || 60;
  document.getElementById("exclude-exts").value = (s.exclude_exts || []).join(", ");
  if (s.last_folder) document.getElementById("folder-input").value = s.last_folder;
  updateProtectionStatus();
  await loadApiKeyStatus();
}

function updateProtectionStatus() {
  const enabled = document.getElementById("auto-check-toggle").checked;
  const el = document.getElementById("p-auto");
  el.textContent = enabled ? "啟用" : "停用";
  el.className = enabled ? "on" : "off";
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
"""TrustmeAntivirus Tkinter 圖形介面（亮色 / 暗黑主題，多執行緒掃描）。"""

from __future__ import annotations

import json
import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from typing import Optional

from .scanner import (
    Scanner,
    ScanResult,
    Blacklist,
    VirusTotalClient,
)
from .utils import (
    compute_sha256,
    classify_severity,
    format_timestamp,
    setup_logging,
    get_resource_path,
)
from . import __version__


# ---------------------------------------------------------------------------
# 主題色彩
# ---------------------------------------------------------------------------

THEMES = {
    "light": {
        "bg": "#f7f8fa",
        "surface": "#ffffff",
        "text": "#1a1a2e",
        "muted": "#64748b",
        "accent": "#2563eb",
        "accent_hover": "#1d4ed8",
        "danger": "#dc2626",
        "border": "#e2e8f0",
        "safe": "#16a34a",
        "warning": "#ca8a04",
        "high": "#dc2626",
        "helpme": "#7f1d1d",
    },
    "dark": {
        "bg": "#0f172a",
        "surface": "#1e293b",
        "text": "#f1f5f9",
        "muted": "#94a3b8",
        "accent": "#3b82f6",
        "accent_hover": "#60a5fa",
        "danger": "#ef4444",
        "border": "#334155",
        "safe": "#22c55e",
        "warning": "#eab308",
        "high": "#ef4444",
        "helpme": "#f87171",
    },
}


class TrustmeAntivirusGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("TrustmeAntivirus - 系統安全防禦")
        self.root.geometry("900x650")
        self.root.minsize(700, 500)

        self.theme_name = "light"
        self.colors = THEMES[self.theme_name]

        self.target_folder: str = ""
        self.blacklist: Optional[Blacklist] = None
        self.vt_client: Optional[VirusTotalClient] = None
        self.scanner_thread: Optional[threading.Thread] = None
        self.scanner: Optional[Scanner] = None
        self.stop_event = threading.Event()

        self._build_ui()
        self._apply_theme()

        # 啟動時載入外部黑名單（若存在）
        self._load_default_blacklist()

        setup_logging(level=__import__("logging").WARNING)

    # ------------------------------------------------------------------
    # UI 建構
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # 頂部標題區
        header = tk.Frame(self.root, bg=self.colors["surface"])
        header.pack(fill="x", padx=20, pady=(16, 4))

        title_label = tk.Label(
            header,
            text="TrustmeAntivirus - 系統安全防禦",
            font=("Segoe UI", 18, "bold"),
            bg=self.colors["surface"],
            fg=self.colors["text"],
        )
        title_label.pack(anchor="w")

        slogan_label = tk.Label(
            header,
            text="Trust me, Your System is Safe.",
            font=("Segoe UI", 11),
            bg=self.colors["surface"],
            fg=self.colors["muted"],
        )
        slogan_label.pack(anchor="w", pady=(2, 0))

        # 主題切換按鈕
        self.theme_btn = tk.Button(
            header,
            text="🌙 切換暗黑模式",
            command=self._toggle_theme,
            bg=self.colors["accent"],
            fg="white",
            activebackground=self.colors["accent_hover"],
            activeforeground="white",
            borderwidth=0,
            padx=12,
            pady=4,
            cursor="hand2",
        )
        self.theme_btn.pack(anchor="e", pady=(8, 0))

        # 操作按鈕區
        btn_frame = tk.Frame(self.root, bg=self.colors["bg"])
        btn_frame.pack(fill="x", padx=20, pady=14)

        self.btn_select = tk.Button(
            btn_frame,
            text="📂 選擇資料夾",
            command=self._select_folder,
            bg=self.colors["surface"],
            fg=self.colors["text"],
            activebackground=self.colors["border"],
            activeforeground=self.colors["text"],
            borderwidth=1,
            relief="solid",
            padx=18,
            pady=8,
            cursor="hand2",
            font=("Segoe UI", 10),
        )
        self.btn_select.pack(side="left", padx=(0, 10))

        self.btn_start = tk.Button(
            btn_frame,
            text="▶ 開始掃描",
            command=self._start_scan,
            bg=self.colors["accent"],
            fg="white",
            activebackground=self.colors["accent_hover"],
            activeforeground="white",
            borderwidth=0,
            padx=18,
            pady=8,
            cursor="hand2",
            font=("Segoo UI", 10, "bold"),
        )
        self.btn_start.pack(side="left", padx=(0, 10))

        self.btn_stop = tk.Button(
            btn_frame,
            text="⏹ 停止掃描",
            command=self._stop_scan,
            bg=self.colors["danger"],
            fg="white",
            activebackground="#b91c1c",
            activeforeground="white",
            borderwidth=0,
            padx=18,
            pady=8,
            cursor="hand2",
            font=("Segoe UI", 10),
            state="disabled",
        )
        self.btn_stop.pack(side="left")

        # 路徑顯示
        self.path_var = tk.StringVar(value="尚未選擇資料夾")
        path_label = tk.Label(
            self.root,
            textvariable=self.path_var,
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            anchor="w",
            padx=10,
            pady=6,
            font=("Segoe UI", 9),
        )
        path_label.pack(fill="x", padx=20)

        # 進度條
        self.progress = ttk.Progressbar(
            self.root,
            orient="horizontal",
            mode="determinate",
            length=100,
        )
        self.progress.pack(fill="x", padx=20, pady=(12, 4))

        self.progress_var = tk.StringVar(value="準備就緒")
        progress_label = tk.Label(
            self.root,
            textvariable=self.progress_var,
            bg=self.colors["bg"],
            fg=self.colors["muted"],
            anchor="w",
            padx=20,
            font=("Segoe UI", 9),
        )
        progress_label.pack(fill="x")

        # 日誌輸出區
        log_frame = tk.Frame(self.root, bg=self.colors["surface"])
        log_frame.pack(fill="both", expand=True, padx=20, pady=(14, 16))

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap="word",
            font=("Consolas", 10),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent"],
            selectforeground="white",
            borderwidth=1,
            relief="solid",
            padx=8,
            pady=8,
        )
        self.log_text.pack(fill="both", expand=True)

        # 底部狀態列
        self.status_var = tk.StringVar(value=f"v{__version__}  ·  就緒")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            anchor="w",
            padx=10,
            pady=4,
            font=("Segoe UI", 8),
        )
        status_bar.pack(fill="x", side="bottom")

    def _apply_theme(self) -> None:
        c = self.colors
        self.root.configure(bg=c["bg"])
        self._recursive_apply(self.root, c)
        self.theme_btn.configure(
            text="☀️ 切換亮色模式" if self.theme_name == "dark" else "🌙 切換暗黑模式",
            bg=c["accent"],
            activebackground=c["accent_hover"],
        )
        self.log_text.configure(bg=c["surface"], fg=c["text"], insertbackground=c["text"])

    def _recursive_apply(self, widget, c) -> None:
        for child in widget.winfo_children():
            try:
                cls = type(child).__name__
                if cls in ("Frame", "tk.Frame", "ttk.Frame"):
                    child.configure(bg=c["bg"])
                elif cls in ("Label", "tk.Label"):
                    child.configure(bg=c["surface"], fg=c["text"])
                elif cls in ("Button", "tk.Button"):
                    # 保留各按鈕自己的指定色彩，僅更新容器背景
                    pass
                elif cls in ("Progressbar", "ttk.Progressbar"):
                    pass
                elif cls in ("ScrolledText", "scrolledtext.ScrolledText"):
                    pass
            except tk.TclError:
                pass
            self._recursive_apply(child, c)

    def _toggle_theme(self) -> None:
        self.theme_name = "dark" if self.theme_name == "light" else "light"
        self.colors = THEMES[self.theme_name]
        self._apply_theme()

    # ------------------------------------------------------------------
    # 事件處理
    # ------------------------------------------------------------------
    def _load_default_blacklist(self) -> None:
        """嘗試載入專案根目錄下的 blacklist.txt 或 blacklist.json。"""
        candidates = [
            os.path.join(os.getcwd(), "blacklist.txt"),
            os.path.join(os.getcwd(), "blacklist.json"),
            get_resource_path("blacklist.txt"),
            get_resource_path("blacklist.json"),
        ]
        for path in candidates:
            if os.path.exists(path):
                self.blacklist = Blacklist(path)
                self._log(f"已載入本地黑名單：{path} ({len(self.blacklist)} 筆)", "info")
                return
        self.blacklist = Blacklist()
        self._log("未找到本地黑名單檔案，將僅依賴 VirusTotal 雲端查詢（若有 API Key）。", "info")

    def _select_folder(self) -> None:
        folder = filedialog.askdirectory(title="選擇要掃描的資料夾")
        if folder:
            self.target_folder = folder
            self.path_var.set(folder)
            self._log(f"已選擇掃描目標：{folder}", "info")
            self.progress["value"] = 0
            self.progress_var.set("準備就緒")

    def _start_scan(self) -> None:
        if not self.target_folder:
            messagebox.showwarning("提示", "請先選擇要掃描的資料夾。")
            return

        # 初始化 VirusTotal 客戶端（API Key 可透過環境變數設定）
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.vt_client = VirusTotalClient(api_key=api_key) if api_key else None

        self.stop_event.clear()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_select.configure(state="disabled")
        self.progress["value"] = 0
        self.progress_var.set("掃描中…")

        self.scanner_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scanner_thread.start()

    def _stop_scan(self) -> None:
        self.stop_event.set()
        self.btn_stop.configure(state="disabled")
        self._log("使用者請求停止掃描，將在目前檔案結束後中斷。", "warn")

    def _run_scan(self) -> None:
        try:
            self.scanner = Scanner(
                target_folder=self.target_folder,
                blacklist=self.blacklist,
                vt_client=self.vt_client,
                on_file_scanned=self._on_file_scanned,
                stop_event=self.stop_event,
            )
            report = self.scanner.run()

            self.root.after(0, self._scan_finished, report)
        except Exception as exc:  # pylint: disable=broad-except
            self.root.after(0, self._scan_error, str(exc))

    def _on_file_scanned(self, result: ScanResult) -> None:
        """每個檔案掃描完成後在主執行緒更新介面。"""
        self.root.after(0, self._update_ui_after_file, result)

    def _update_ui_after_file(self, result: ScanResult) -> None:
        with self.scanner.report._lock if self.scanner else threading.Lock():
            scanned = self.scanner.report.scanned_files
            total = self.scanner.report.total_files

        if total > 0:
            pct = scanned / total * 100
        else:
            pct = 0
        self.progress["value"] = pct
        self.progress_var.set(f"{scanned}/{total}  ·  {os.path.basename(result.path)}")

        # 日誌輸出
        if result.status == "error":
            self._log(f"[錯誤] {result.path} - {result.error_message}", "error")
        elif result.status == "threat":
            sev = result.severity
            sev_color = {
                "Low": "warning",
                "Medium": "high",
                "High": "high",
                "Helpme": "helpme",
            }.get(sev, "text")
            msg = (
                f"[風險] {result.path}  | 雜湊: {result.sha256[:16]}...  | "
                f"本地黑名單: {'是' if result.local_malicious else '否'}  | "
                f"VT: {result.vt_detected}/{result.vt_total}  | 等級: {sev}"
            )
            self._log(msg, sev_color)
            self._show_severity_alert(sev, result.path)
        else:
            self._log(f"[安全] {result.path}", "safe")

    def _show_severity_alert(self, severity: str, file_path: str) -> None:
        """Medium 以上彈出提醒，Helpme 強調劇烈病毒。"""
        if severity == "Helpme":
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "🚨 偵測到劇烈病毒 (Helpme)",
                    f"檔案：{file_path}\n等級：Helpme（極高風險）\n建議立即隔離或刪除，並進行系統全面檢查。",
                ),
            )
        elif severity in ("Medium", "High"):
            self.root.after(
                0,
                lambda: messagebox.showwarning(
                    f"⚠️ 偵測到風險檔案 ({severity})",
                    f"檔案：{file_path}\n等級：{severity}\n建議盡快刪除或警惕此檔案。",
                ),
            )

    def _log(self, message: str, level: str = "info") -> None:
        c = self.colors
        level_map = {
            "safe": c["safe"],
            "warn": c["warning"],
            "error": c["danger"],
            "high": c["high"],
            "helpme": c["helpme"],
            "info": c["muted"],
        }
        tag = level
        timestamp = format_timestamp()
        line = f"[{timestamp}] {message}\n"

        self.log_text.insert("end", line)
        self.log_text.tag_config(tag, foreground=level_map.get(level, c["text"]))
        # 簡化：直接插入帶顏色 tag 需要分段，這裡先整行顏色設為該 level
        self.log_text.tag_add(tag, "end-2c linestart", "end-1c")
        self.log_text.see("end")

    def _scan_finished(self, report) -> None:
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_select.configure(state="normal")
        self.progress["value"] = 100
        self.progress_var.set(f"掃描完成：{report.scanned_files}/{report.total_files} 個檔案，發現 {report.risk_files} 個風險")
        self.status_var.set(f"v{__version__}  ·  掃描完成，耗時 {report.duration_seconds:.1f} 秒")

        self._log("=" * 60, "info")
        self._log(f"掃描報告：{report.target_folder}", "info")
        self._log(f"總檔案數：{report.total_files}", "info")
        self._log(f"掃描數：{report.scanned_files}", "info")
        self._log(f"錯誤數：{report.error_files}", "warn" if report.error_files else "info")
        self._log(f"風險檔案數：{report.risk_files}", "helpme" if report.risk_files else "safe")
        self._log(f"耗時：{report.duration_seconds:.1f} 秒", "info")
        self._log("=" * 60, "info")

        # 自動儲存 JSON 報告
        out_path = os.path.join(os.getcwd(), "scan_report.json")
        try:
            report.save_report_json(out_path)
            self._log(f"報告已儲存：{out_path}", "info")
        except Exception as exc:
            self._log(f"儲存報告失敗：{exc}", "error")

        if report.risk_files > 0:
            messagebox.showinfo(
                "掃描完成",
                f"掃描結束，發現 {report.risk_files} 個風險檔案。\n詳情請查看日誌與 scan_report.json。",
            )
        else:
            messagebox.showinfo("掃描完成", "未發現風險檔案，系統安全。")

    def _scan_error(self, error_msg: str) -> None:
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_select.configure(state="normal")
        self.progress_var.set("掃描發生錯誤")
        self._log(f"[例外] {error_msg}", "error")
        messagebox.showerror("掃描錯誤", error_msg)


def main() -> None:
    root = tk.Tk()
    app = TrustmeAntivirusGUI(root)
    root.mainloop()
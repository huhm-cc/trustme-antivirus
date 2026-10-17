"""TrustmeAntivirus CustomTkinter 圖形介面（現代圓角 UI、暗色模式、多執行緒掃描）。"""

from __future__ import annotations

import os
import threading
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

from .scanner import (
    SmartScanner,
    ScanResult,
    Blacklist,
    VirusTotalClient,
    NVIDIAClient,
)
from .utils import format_timestamp, setup_logging, get_resource_path
from . import __version__

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# 日誌顏色（深淺色通用）
LOG_COLORS = {
    "safe": "#22c55e",
    "warn": "#eab308",
    "error": "#ef4444",
    "high": "#ef4444",
    "helpme": "#f87171",
    "info": "#94a3b8",
    "text": "#e2e8f0",
}


class TrustmeAntivirusGUI:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("TrustmeAntivirus - 系統安全防禦")
        self.root.geometry("960x680")
        self.root.minsize(720, 520)

        self.theme_mode = "dark"

        self.target_folder: str = ""
        self.blacklist: Optional[Blacklist] = None
        self.vt_client: Optional[VirusTotalClient] = None
        self.nvidia_client: Optional[NVIDIAClient] = None
        self.scanner_thread: Optional[threading.Thread] = None
        self.scanner: Optional[SmartScanner] = None
        self.stop_event = threading.Event()

        # 動畫狀態
        self._anim_running = False
        self._anim_dot_count = 0

        self._build_ui()

        # 啟動時載入外部黑名單（若存在）
        self._load_default_blacklist()

        # NVIDIA 智慧檢查狀態
        nvidia_key = os.environ.get("NVIDIA_API_KEY", "")
        if nvidia_key:
            self._log("NVIDIA 智慧檢查已啟用（模型：nemotron-3.5-lightning-30b-a3b）", "info")
        else:
            self._log("未設定 NVIDIA_API_KEY，將跳過 AI 智慧檢查。", "info")

        setup_logging(level=__import__("logging").WARNING)

    # ------------------------------------------------------------------
    # UI 建構
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # 頂部標題區
        header = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="TrustmeAntivirus - 系統安全防禦",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).pack(anchor="w", padx=24, pady=(20, 0))

        ctk.CTkLabel(
            header,
            text="Trust me, Your System is Safe.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8",
        ).pack(anchor="w", padx=24, pady=(2, 12))

        # 主題切換按鈕
        self.theme_btn = ctk.CTkButton(
            header, text="☀️ 切換亮色模式", width=150, height=32, corner_radius=8,
            command=self._toggle_theme,
        )
        self.theme_btn.place(relx=1.0, rely=0.15, x=-24, anchor="ne")

        # 按鈕列
        controls = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        controls.pack(fill="x", padx=24, pady=(16, 8))

        self.btn_select = ctk.CTkButton(
            controls, text="📂 選擇資料夾", width=140, height=42, corner_radius=10,
            command=self._select_folder,
        )
        self.btn_select.pack(side="left", padx=(0, 10))

        self.btn_start = ctk.CTkButton(
            controls, text="▶ 開始掃描", width=130, height=42, corner_radius=10,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._start_scan,
        )
        self.btn_start.pack(side="left", padx=(0, 10))

        self.btn_stop = ctk.CTkButton(
            controls, text="⏹ 停止掃描", width=130, height=42, corner_radius=10,
            fg_color="#dc2626", hover_color="#991b1b", state="disabled",
            command=self._stop_scan,
        )
        self.btn_stop.pack(side="left")

        # 路徑顯示
        self.path_var = ctk.StringVar(value="尚未選擇資料夾")
        ctk.CTkLabel(
            self.root, textvariable=self.path_var, anchor="w",
            font=ctk.CTkFont(size=12), text_color="#94a3b8",
        ).pack(fill="x", padx=28)

        # 進度條
        self.progress = ctk.CTkProgressBar(self.root, height=14, corner_radius=7)
        self.progress.pack(fill="x", padx=24, pady=(16, 2))
        self.progress.set(0)

        self.progress_var = ctk.StringVar(value="準備就緒")
        ctk.CTkLabel(
            self.root, textvariable=self.progress_var, anchor="w",
            font=ctk.CTkFont(size=12), text_color="#94a3b8",
        ).pack(fill="x", padx=28)

        # 日誌輸出區
        self.log_text = ctk.CTkTextbox(
            self.root, corner_radius=10, font=ctk.CTkFont(family="Consolas", size=13),
        )
        self.log_text.pack(fill="both", expand=True, padx=24, pady=(12, 8))

        # 底部狀態列
        self.status_var = ctk.StringVar(value=f"v{__version__}  ·  就緒")
        ctk.CTkLabel(
            self.root, textvariable=self.status_var, anchor="w",
            font=ctk.CTkFont(size=11), text_color="#64748b",
        ).pack(fill="x", side="bottom", padx=28, pady=(0, 10))

    def _toggle_theme(self) -> None:
        self.theme_mode = "light" if self.theme_mode == "dark" else "dark"
        ctk.set_appearance_mode(self.theme_mode)
        self.theme_btn.configure(
            text="🌙 切換暗色模式" if self.theme_mode == "light" else "☀️ 切換亮色模式"
        )

    # ------------------------------------------------------------------
    # 事件處理
    # ------------------------------------------------------------------
    def _load_default_blacklist(self) -> None:
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
            self.progress.set(0)
            self.progress_var.set("準備就緒")

    def _start_scan(self) -> None:
        if not self.target_folder:
            messagebox.showwarning("提示", "請先選擇要掃描的資料夾。")
            return

        # 初始化 VirusTotal 客戶端
        vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.vt_client = VirusTotalClient(api_key=vt_api_key) if vt_api_key else None

        # 初始化 NVIDIA 智慧檢查客戶端
        nvidia_api_key = os.environ.get("NVIDIA_API_KEY", "")
        self.nvidia_client = NVIDIAClient(api_key=nvidia_api_key) if nvidia_api_key else None

        self.stop_event.clear()
        self._anim_running = True
        self._anim_dot_count = 0
        self._animate_progress()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_select.configure(state="disabled")
        self.progress.set(0)
        self.progress_var.set("掃描中…")

        self.scanner_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scanner_thread.start()

    def _stop_scan(self) -> None:
        self.stop_event.set()
        self.btn_stop.configure(state="disabled")
        self._log("使用者請求停止掃描，將在目前檔案結束後中斷。", "warn")

    def _run_scan(self) -> None:
        try:
            self.scanner = SmartScanner(
                target_folder=self.target_folder,
                blacklist=self.blacklist,
                vt_client=self.vt_client,
                nvidia_client=self.nvidia_client,
                on_file_scanned=self._on_file_scanned,
                stop_event=self.stop_event,
            )
            report = self.scanner.run()
            self.root.after(0, self._scan_finished, report)
        except Exception as exc:  # pylint: disable=broad-except
            self.root.after(0, self._scan_error, str(exc))
        finally:
            self._anim_running = False

    # ------------------------------------------------------------------
    # 動畫
    # ------------------------------------------------------------------
    def _animate_progress(self) -> None:
        if not self._anim_running:
            return
        self._anim_dot_count = (self._anim_dot_count + 1) % 4
        dots = "." * self._anim_dot_count
        self.progress_var.set(f"掃描中{dots}")
        self.root.after(400, self._animate_progress)

    # ------------------------------------------------------------------
    # 掃描結果更新
    # ------------------------------------------------------------------
    def _on_file_scanned(self, result: ScanResult) -> None:
        self.root.after(0, self._update_ui_after_file, result)

    def _update_ui_after_file(self, result: ScanResult) -> None:
        if self.scanner:
            scanned = self.scanner.report.scanned_files
            total = self.scanner.report.total_files
        else:
            scanned, total = 0, 0

        if total > 0:
            self.progress.set(scanned / total)
        self.progress_var.set(f"{scanned}/{total}  ·  {os.path.basename(result.path)}")

        if result.status == "error":
            self._log(f"[錯誤] {result.path} - {result.error_message}", "error")
        elif result.status == "threat":
            sev = result.severity
            sev_color = {
                "Low": "warn", "Medium": "high", "High": "high", "Helpme": "helpme",
            }.get(sev, "text")
            ai_info = ""
            if result.ai_threat_level:
                ai_info = (
                    f"  | AI: {result.ai_threat_level} ({result.ai_confidence}%)"
                    f"  | 建議: {result.ai_action}"
                )
            msg = (
                f"[風險] {result.path}  | 雜湊: {result.sha256[:16]}...  | "
                f"本地黑名單: {'是' if result.local_malicious else '否'}  | "
                f"VT: {result.vt_detected}/{result.vt_total}  | 等級: {sev}{ai_info}"
            )
            self._log(msg, sev_color)
            if result.ai_reasoning:
                self._log(f"    🤖 AI 分析：{result.ai_reasoning}", "info")
            self._show_severity_alert(sev, result.path)
        else:
            self._log(f"[安全] {result.path}", "safe")

    def _show_severity_alert(self, severity: str, file_path: str) -> None:
        if severity == "Helpme":
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "🚨 偵測到劇烈病毒 (Helpme)",
                    f"檔案：{file_path}\n等級：Helpme（極高風險）\n"
                    "建議立即隔離或刪除，並進行系統全面檢查。",
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
        tag = level
        timestamp = format_timestamp()
        line = f"[{timestamp}] {message}"
        self.log_text.tag_config(tag, foreground=LOG_COLORS.get(level, LOG_COLORS["text"]))
        self.log_text.insert("end", line + "\n", tag)
        self.log_text.see("end")

    def _scan_finished(self, report) -> None:
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_select.configure(state="normal")
        self.progress.set(1.0)
        self.progress_var.set(
            f"掃描完成：{report.scanned_files}/{report.total_files} 個檔案，"
            f"發現 {report.risk_files} 個風險"
        )
        self.status_var.set(
            f"v{__version__}  ·  掃描完成，耗時 {report.duration_seconds:.1f} 秒"
        )

        self._log("=" * 60, "info")
        self._log(f"掃描報告：{report.target_folder}", "info")
        self._log(f"總檔案數：{report.total_files}", "info")
        self._log(f"掃描數：{report.scanned_files}", "info")
        self._log(f"錯誤數：{report.error_files}", "warn" if report.error_files else "info")
        self._log(f"風險檔案數：{report.risk_files}", "helpme" if report.risk_files else "safe")

        # NVIDIA AI 智慧檢查統計
        ai_analyzed = sum(1 for r in report.risks if r.ai_threat_level)
        ai_critical = sum(1 for r in report.risks if r.ai_threat_level == "Critical")
        if ai_analyzed > 0:
            self._log(f"NVIDIA AI 智慧分析：{ai_analyzed} 個檔案", "info")
            if ai_critical > 0:
                self._log(f"⚠️ AI 判定為極高風險 (Critical)：{ai_critical} 個檔案", "helpme")

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
                f"掃描結束，發現 {report.risk_files} 個風險檔案。\n"
                "詳情請查看日誌與 scan_report.json。",
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
    root = ctk.CTk()
    app = TrustmeAntivirusGUI(root)
    root.mainloop()
"""TrustmeAntivirus 前後端橋接層（pywebview js_api）。

提供 JS 可呼叫的 API：掃描控制、狀態輪詢、日誌增量、
隔離區管理、掃描歷史、系統資訊、設定與自動背景檢查。
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional

from .scanner import (
    SmartScanner,
    ScanResult,
    Blacklist,
    VirusTotalClient,
    NVIDIAClient,
    Quarantine,
    HistoryManager,
)
from .utils import format_timestamp, get_system_info, get_resource_path
from . import __version__


class BridgeAPI:
    """pywebview js_api 橋接類別。"""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.getcwd()
        os.makedirs(self.base_dir, exist_ok=True)
        self.settings_path = os.path.join(self.base_dir, "settings.json")

        # 狀態
        self._lock = threading.Lock()
        self._logs: list[dict] = []          # [{index, text, level}]
        self._log_index = 0
        self._notifications: list[dict] = []  # 待前端顯示的通知
        self.scanner: Optional[SmartScanner] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.is_scanning = False
        self._current_file = ""
        self.last_scan_finished_at = ""
        self._last_target_folder = ""
        self._last_scan_mode = "full"

        # 元件
        self.blacklist = Blacklist(self._find_blacklist_path())
        self.quarantine = Quarantine(os.path.join(self.base_dir, "quarantine"))
        self.history = HistoryManager(self.base_dir)
        self.settings = self._load_settings()

        self._log(f"TrustmeAntivirus v{__version__} 已啟動。", "info")
        if self._get_nv_key():
            self._log("NVIDIA 智慧檢查已啟用（nemotron-3.5-lightning-30b-a3b）", "info")
        else:
            self._log("未設定 NVIDIA API Key，可在「設定」頁填入以啟用 AI 智慧檢查。", "info")
        if self._get_vt_key():
            self._log("VirusTotal 雲端查詢已啟用。", "info")
        else:
            self._log("未設定 VirusTotal API Key，可在「設定」頁填入以啟用雲端查詢。", "info")

        # 自動背景檢查執行緒
        self._auto_thread = threading.Thread(target=self._auto_check_loop, daemon=True)
        self._auto_thread.start()

    # ------------------------------------------------------------------
    # 設定
    # ------------------------------------------------------------------
    def _load_settings(self) -> dict:
        defaults = {
            "auto_check_enabled": False,
            "auto_check_interval_min": 60,
            "exclude_exts": [],
            "last_folder": "",
            "vt_api_key": "",
            "nvidia_api_key": "",
        }
        try:
            with open(self.settings_path, "r", encoding="utf-8") as f:
                defaults.update(json.load(f))
        except (OSError, json.JSONDecodeError):
            pass
        return defaults

    def _save_settings(self) -> None:
        try:
            with open(self.settings_path, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _find_blacklist_path(self) -> Optional[str]:
        for name in ("blacklist.txt", "blacklist.json"):
            for base in (self.base_dir, os.path.dirname(os.path.abspath(__file__)),
                         get_resource_path(".")):
                path = os.path.join(base, name)
                if os.path.exists(path):
                    return path
        return None

    # ------------------------------------------------------------------
    # 日誌與通知
    # ------------------------------------------------------------------
    def _log(self, text: str, level: str = "info") -> None:
        with self._lock:
            self._log_index += 1
            self._logs.append({"index": self._log_index, "text": text, "level": level})

    def _notify(self, text: str, kind: str = "info") -> None:
        with self._lock:
            self._notifications.append({
                "id": int(time.time() * 1000),
                "text": text,
                "kind": kind,
            })

    def _get_vt_key(self) -> str:
        """取得實際生效的 VirusTotal Key（設定檔優先，環境變數備援）。"""
        return (self.settings.get("vt_api_key", "")
                or os.environ.get("VIRUSTOTAL_API_KEY", "")).strip()

    def _get_nv_key(self) -> str:
        """取得實際生效的 NVIDIA Key（設定檔優先，環境變數備援）。"""
        return (self.settings.get("nvidia_api_key", "")
                or os.environ.get("NVIDIA_API_KEY", "")).strip()

    @staticmethod
    def _mask_key(key: str) -> str:
        if not key:
            return ""
        if len(key) <= 12:
            return "*" * len(key)
        return f"{key[:6]}…{key[-4:]}（已設定）"

    # ------------------------------------------------------------------
    # JS API：API 金鑰管理
    # ------------------------------------------------------------------
    def get_api_keys(self) -> dict:
        """回傳金鑰設定狀態（不回傳完整金鑰）。"""
        vt = self._get_vt_key()
        nv = self._get_nv_key()
        return {
            "vt_set": bool(vt),
            "vt_masked": self._mask_key(vt),
            "vt_from_env": not self.settings.get("vt_api_key") and bool(vt),
            "nvidia_set": bool(nv),
            "nvidia_masked": self._mask_key(nv),
            "nvidia_from_env": not self.settings.get("nvidia_api_key") and bool(nv),
        }

    def set_api_keys(self, vt_key: str, nvidia_key: str) -> dict:
        """儲存 API 金鑰到設定檔（留空即清除設定檔中的金鑰）。"""
        try:
            self.settings["vt_api_key"] = (vt_key or "").strip()
            self.settings["nvidia_api_key"] = (nvidia_key or "").strip()
            self._save_settings()

            vt = self._get_vt_key()
            nv = self._get_nv_key()
            self._log(
                f"金鑰狀態更新 — VirusTotal: {'已啟用' if vt else '未設定'}，"
                f"NVIDIA: {'已啟用' if nv else '未設定'}",
                "info",
            )
            return {"ok": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"ok": False, "error": str(exc)}

    def open_env_window(self) -> dict:
        """開啟 Windows 系統環境變數編輯視窗。"""
        try:
            import subprocess
            subprocess.Popen(
                ["rundll32", "sysdm.cpl,EditEnvironmentVariables"]
            )
            return {"ok": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # JS API：資料夾選擇
    # ------------------------------------------------------------------
    def select_folder(self) -> dict:
        """彈出資料夾選擇對話框（使用 tkinter 原生對話框，避開
        pywebview 在 js_api 執行緒中彈不出對話框的問題）。"""
        try:
            import tkinter as tk
            from tkinter import filedialog

            tk_root = tk.Tk()
            tk_root.withdraw()
            tk_root.attributes("-topmost", True)
            folder = filedialog.askdirectory(title="選擇要掃描的資料夾")
            tk_root.destroy()

            if folder:
                self._last_target_folder = folder
                self.settings["last_folder"] = folder
                self._save_settings()
                self._log(f"已選擇掃描目標：{folder}", "info")
                return {"ok": True, "path": folder}
            return {"ok": False, "path": ""}
        except Exception as exc:  # pylint: disable=broad-except
            return {"ok": False, "path": "", "error": str(exc)}

    # ------------------------------------------------------------------
    # JS API：掃描控制
    # ------------------------------------------------------------------
    def start_scan(self, folder: str, mode: str = "full") -> dict:
        folder = (folder or self._last_target_folder or self.settings.get("last_folder", "")).strip()
        if not folder or not os.path.isdir(folder):
            return {"ok": False, "error": "請先選擇有效的資料夾"}

        if self.is_scanning:
            return {"ok": False, "error": "掃描正在進行中"}

        self._last_target_folder = folder
        self._last_scan_mode = mode
        self._stop_event.clear()
        self.is_scanning = True

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(folder, mode),
            daemon=True,
        )
        self._scan_thread.start()
        mode_text = "快速掃描" if mode == "quick" else "完整掃描"
        self._log(f"開始{mode_text}：{folder}", "info")
        return {"ok": True}

    def stop_scan(self) -> dict:
        self._stop_event.set()
        self._log("使用者請求停止掃描，將在目前檔案結束後中斷。", "warn")
        return {"ok": True}

    def _run_scan(self, folder: str, mode: str) -> None:
        try:
            self.scanner = SmartScanner(
                target_folder=folder,
                blacklist=self.blacklist,
                vt_client=VirusTotalClient(api_key=self._get_vt_key()) if self._get_vt_key() else None,
                nvidia_client=NVIDIAClient(api_key=self._get_nv_key()) if self._get_nv_key() else None,
                on_file_scanned=self._on_file_scanned,
                stop_event=self._stop_event,
                mode=mode,
                exclude_exts=self.settings.get("exclude_exts", []),
            )
            report = self.scanner.run()

            self.history.append(report, mode=mode)
            self.last_scan_finished_at = report.finished_at
            self._log("=" * 60, "info")
            self._log(f"掃描完成：{report.scanned_files}/{report.total_files}，"
                      f"風險 {report.risk_files} 個，錯誤 {report.error_files} 個，"
                      f"耗時 {report.duration_seconds:.1f} 秒", "info")
            self._log("=" * 60, "info")

            out_path = os.path.join(self.base_dir, "scan_report.json")
            try:
                report.save_report_json(out_path)
                self._log(f"報告已儲存：{out_path}", "info")
            except Exception as exc:  # pylint: disable=broad-except
                self._log(f"儲存報告失敗：{exc}", "error")

            if report.risk_files > 0:
                self._notify(f"掃描完成，發現 {report.risk_files} 個風險檔案", "risk")
            else:
                self._notify("掃描完成，未發現風險檔案 ✅", "safe")
        except Exception as exc:  # pylint: disable=broad-except
            self._log(f"[例外] {exc}", "error")
            self._notify(f"掃描發生錯誤：{exc}", "risk")
        finally:
            self.is_scanning = False

    def _on_file_scanned(self, result: ScanResult) -> None:
        """掃描回調：寫入日誌（由掃描執行緒呼叫）。

        安全檔案不逐行寫入日誌（只計數），避免海量檔案時
        前端 DOM 更不及造成介面卡頓。
        """
        self._current_file = result.path

        if result.status == "error":
            self._log(f"[錯誤] {result.path} - {result.error_message}", "error")
            return

        if result.status == "threat":
            sev = result.severity
            level = {"Low": "warn", "Medium": "high", "High": "high"}.get(sev, "helpme")
            ai_info = ""
            if result.ai_threat_level:
                ai_info = (f"  | AI: {result.ai_threat_level} ({result.ai_confidence}%)"
                           f"  | 建議: {result.ai_action}")
            self._log(
                f"[風險] {result.path}  | 雜湊: {result.sha256[:16]}...  | "
                f"本地: {'是' if result.local_malicious else '否'}  | "
                f"VT: {result.vt_detected}/{result.vt_total}  | 等級: {sev}{ai_info}",
                level,
            )
            if result.ai_reasoning:
                self._log(f"    🤖 AI 分析：{result.ai_reasoning}", "info")
        # 安全檔案：不寫日誌，僅由 get_status 的計數呈現

    # ------------------------------------------------------------------
    # JS API：狀態輪詢
    # ------------------------------------------------------------------
    def get_status(self) -> dict:
        scanned, total = 0, 0
        risks, errors = 0, 0
        if self.scanner:
            report = self.scanner.report
            scanned = report.scanned_files
            total = report.total_files
            risks = report.risk_files
            errors = report.error_files

        with self._lock:
            notifications = list(self._notifications)
            self._notifications.clear()

        return {
            "version": __version__,
            "is_scanning": self.is_scanning,
            "scanned": scanned,
            "total": total,
            "risks": risks,
            "errors": errors,
            "safe": scanned - risks - errors if scanned > risks + errors else 0,
            "progress": (scanned / total) if total > 0 else 0,
            "current_file": self._current_file,
            "last_scan_finished_at": self.last_scan_finished_at,
            "target_folder": self._last_target_folder,
            "mode": self._last_scan_mode,
            "vt_enabled": bool(self._get_vt_key()),
            "nvidia_enabled": bool(self._get_nv_key()),
            "notifications": notifications,
            "timestamp": format_timestamp(),
        }

    def get_log(self, since: int = 0) -> dict:
        with self._lock:
            lines = [l for l in self._logs if l["index"] > since]
        return {"lines": lines, "latest": self._log_index}

    # ------------------------------------------------------------------
    # JS API：隔離區
    # ------------------------------------------------------------------
    def quarantine_file(self, path: str, sha256: str = "") -> dict:
        result = self.quarantine.move_to_quarantine(path, sha256)
        if result.get("ok"):
            self._log(f"已隔離：{path}", "warn")
            self._notify(f"檔案已隔離：{os.path.basename(path)}", "risk")
        else:
            self._log(f"隔離失敗：{result.get('error')}", "error")
        return result

    def get_quarantine(self) -> dict:
        return {"items": self.quarantine.list_all()}

    def restore_quarantined(self, name: str) -> dict:
        result = self.quarantine.restore(name)
        self._log(f"還原結果：{result}", "info")
        return result

    def delete_quarantined(self, name: str) -> dict:
        result = self.quarantine.delete_permanently(name)
        self._log(f"永久刪除結果：{result}", "warn")
        return result

    # ------------------------------------------------------------------
    # JS API：歷史與報告
    # ------------------------------------------------------------------
    def get_history(self) -> dict:
        return {"items": self.history.list_all()}

    def export_csv(self) -> dict:
        """將最近一次掃描報告匯出為 CSV。"""
        try:
            report_path = os.path.join(self.base_dir, "scan_report.json")
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            csv_path = os.path.join(self.base_dir, "scan_report.csv")
            with open(csv_path, "w", encoding="utf-8-sig") as f:
                f.write("path,sha256,severity,local_malicious,vt_detected,vt_total,"
                        "ai_threat_level,ai_confidence,ai_action,status\n")
                for r in data.get("risks", []):
                    f.write(
                        f"\"{r.get('path','')}\",{r.get('sha256','')},{r.get('severity','')},"
                        f"{r.get('local_malicious','')},{r.get('vt_detected',0)},"
                        f"{r.get('vt_total',0)},{r.get('ai_threat_level','')},"
                        f"{r.get('ai_confidence',0)},{r.get('ai_action','')},"
                        f"{r.get('status','')}\n"
                    )
            self._log(f"CSV 報告已匯出：{csv_path}", "info")
            return {"ok": True, "path": csv_path}
        except Exception as exc:  # pylint: disable=broad-except
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # JS API：系統資訊與設定
    # ------------------------------------------------------------------
    def get_system_info(self) -> dict:
        return get_system_info()

    def get_settings(self) -> dict:
        return self.settings

    def save_settings(self, auto_check_enabled: bool, auto_check_interval_min: int,
                      exclude_exts: str) -> dict:
        try:
            self.settings["auto_check_enabled"] = bool(auto_check_enabled)
            self.settings["auto_check_interval_min"] = max(1, int(auto_check_interval_min))
            exts = [e.strip().lstrip(".").lower() for e in exclude_exts.split(",") if e.strip()]
            self.settings["exclude_exts"] = exts
            self._save_settings()
            self._log("設定已儲存。", "info")
            return {"ok": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # 自動背景檢查
    # ------------------------------------------------------------------
    def _auto_check_loop(self) -> None:
        """每分鐘檢查一次是否該自動掃描。"""
        last_auto_scan = 0.0
        while True:
            time.sleep(60)
            try:
                if not self.settings.get("auto_check_enabled", False):
                    continue
                if self.is_scanning:
                    continue

                interval_min = self.settings.get("auto_check_interval_min", 60)
                now = time.time()
                if now - last_auto_scan < interval_min * 60:
                    continue

                folder = self.settings.get("last_folder", "")
                if folder and os.path.isdir(folder):
                    last_auto_scan = now
                    self._notify(f"🛡️ 自動背景檢查啟動（快速掃描）：{folder}", "info")
                    self._log("自動背景檢查啟動。", "info")
                    self.start_scan(folder, mode="quick")
            except Exception:  # pylint: disable=broad-except
                pass
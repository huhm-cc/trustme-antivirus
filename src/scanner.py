"""TrustmeAntivirus 掃描模組：遞迴掃描、本地黑名單比對、VirusTotal 雲端查詢."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Callable, Optional

import requests

from .utils import compute_sha256, classify_severity, format_timestamp
from . import __version__


# ---------------------------------------------------------------------------
# 資料結構
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """單一檔案掃描結果。"""

    path: str
    sha256: str
    size: int
    local_malicious: bool = False
    vt_detected: int = 0
    vt_total: int = 0
    severity: str = "Safe"
    status: str = "scanned"  # scanned / error / skipped
    error_message: str = ""
    # NVIDIA 智慧檢查欄位
    ai_threat_level: str = ""
    ai_confidence: int = 0
    ai_action: str = ""
    ai_reasoning: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    """整體掃描報告。"""

    target_folder: str
    started_at: str
    finished_at: str = ""
    total_files: int = 0
    scanned_files: int = 0
    error_files: int = 0
    risk_files: int = 0
    risks: list[ScanResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target_folder": self.target_folder,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "error_files": self.error_files,
            "risk_files": self.risk_files,
            "duration_seconds": round(self.duration_seconds, 3),
            "risks": [r.to_dict() for r in self.risks],
        }

    def save_report_json(self, output_path: str) -> None:
        """將報告寫入 JSON 檔案。"""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# 本地黑名單
# ---------------------------------------------------------------------------

class Blacklist:
    """本地 SHA-256 惡意雜湊黑名單（HashSet）。"""

    def __init__(self, blacklist_path: Optional[str] = None):
        self._hashes: set[str] = set()
        self.path = blacklist_path
        if blacklist_path and os.path.exists(blacklist_path):
            self.load(blacklist_path)

    def load(self, path: str) -> None:
        """從文字檔或 JSON 載入黑名單。

        支援格式：
        - 純文字：每行一個 SHA-256 雜湊
        - JSON：{"hashes": ["...", "..."]} 或 ["...", "..."]
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return

            # 嘗試解析 JSON
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    items = data.get("hashes", [])
                elif isinstance(data, list):
                    items = data
                else:
                    items = []
            except json.JSONDecodeError:
                # 純文字：每行一個雜湊
                items = [line.strip() for line in content.splitlines() if line.strip()]

            for h in items:
                h = h.strip().lower()
                if h:
                    self._hashes.add(h)
        except (OSError, PermissionError) as exc:
            # 載入失敗不應阻止掃描，僅記錄並繼續
            import logging
            logging.warning("載入黑名單失敗 %s: %s", path, exc)

    def contains(self, sha256: str) -> bool:
        return sha256.lower() in self._hashes

    def __len__(self) -> int:
        return len(self._hashes)


# ---------------------------------------------------------------------------
# VirusTotal API v3（預留，免費版 Rate Limit 每分鐘 4 次）
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """VirusTotal API v3 用戶端，內建簡易速率限制。"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, min_interval: float = 15.0):
        """
        參數：
            api_key: VirusTotal API Key。未提供時查詢會跳過並回傳 None。
            min_interval: 兩次請求間的最小間隔秒數（免費版建議 >= 15 秒）。
        """
        self.api_key = api_key
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._last_request_time: float = 0.0

    def _wait_for_rate_limit(self) -> None:
        """確保兩次 API 請求間隔不小於 min_interval。"""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.min_interval and self._last_request_time > 0:
                time.sleep(self.min_interval - elapsed)
            self._last_request_time = time.time()

    def lookup_by_hash(self, sha256: str) -> Optional[dict]:
        """根據 SHA-256 查詢 VirusTotal 檔案報告。

        回傳：
            解析後的 JSON 字典；若無 API Key、請求失敗或找不到檔案則回傳 None。
        """
        if not self.api_key:
            return None

        self._wait_for_rate_limit()

        url = f"{self.BASE_URL}/files/{sha256}"
        headers = {"x-apikey": self.api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                return None  # 未在 VirusTotal 資料庫中
            if resp.status_code == 429:
                # 觸碰 Rate Limit，稍後重試一次
                time.sleep(self.min_interval)
                resp2 = requests.get(url, headers=headers, timeout=15)
                if resp2.status_code == 200:
                    return resp2.json()
                return None
            return None
        except requests.RequestException:
            return None

    @staticmethod
    def parse_detections(vt_response: Optional[dict]) -> tuple[int, int]:
        """從 VirusTotal 回應解析偵測數與總引擎數。

        回傳：
            (detected_count, total_engines)
        """
        if not vt_response:
            return 0, 0
        try:
            stats = vt_response["data"]["attributes"]["last_analysis_stats"]
            detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            return detected, total
        except (KeyError, TypeError):
            return 0, 0


# ---------------------------------------------------------------------------
# 掃描器
# ---------------------------------------------------------------------------

class Scanner:
    """遞迴掃描目標資料夾，支援本地黑名單與 VirusTotal 雲端查詢。"""

    # 快速掃描模式：僅檢查常見可執行 / 指令碼副檔名
    QUICK_SCAN_EXTS = {
        ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".jse", ".wsf", ".wsh", ".msi", ".scr", ".com", ".pif", ".jar",
        ".hta", ".lnk", ".py", ".pyw",
    }

    def __init__(
        self,
        target_folder: str,
        blacklist: Optional[Blacklist] = None,
        vt_client: Optional[VirusTotalClient] = None,
        on_file_scanned: Optional[Callable[[ScanResult], None]] = None,
        stop_event: Optional[threading.Event] = None,
        mode: str = "full",
        exclude_exts: Optional[list[str]] = None,
    ):
        self.target_folder = os.path.abspath(target_folder)
        self.blacklist = blacklist or Blacklist()
        self.vt_client = vt_client
        self.on_file_scanned = on_file_scanned
        self.stop_event = stop_event or threading.Event()
        self.mode = mode
        self.exclude_exts = {e.lower() for e in (exclude_exts or [])}

        self.report = ScanReport(
            target_folder=self.target_folder,
            started_at=format_timestamp(),
        )
        self._lock = threading.Lock()

    def stop(self) -> None:
        self.stop_event.set()

    def _collect_files(self) -> list[str]:
        """遞迴蒐集所有檔案路徑，依掃描模式與排除清單過濾。"""
        files: list[str] = []
        for root, _dirs, filenames in os.walk(self.target_folder):
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if self.mode == "quick" and ext not in self.QUICK_SCAN_EXTS:
                    continue
                if ext in self.exclude_exts:
                    continue
                files.append(os.path.join(root, name))
        return files

    def _scan_single(self, file_path: str) -> ScanResult:
        """掃描單一檔案。"""
        try:
            size = os.path.getsize(file_path)
        except OSError:
            size = 0

        sha256 = compute_sha256(file_path)
        if sha256 is None:
            result = ScanResult(
                path=file_path,
                sha256="",
                size=size,
                status="error",
                error_message="無法讀取檔案（權限不足或被鎖定）",
            )
            with self._lock:
                self.report.error_files += 1
            if self.on_file_scanned:
                self.on_file_scanned(result)
            return result

        result = ScanResult(
            path=file_path,
            sha256=sha256,
            size=size,
        )

        # 本地黑名單比對
        if self.blacklist.contains(sha256):
            result.local_malicious = True
            result.severity = "Helpme"
            result.status = "threat"

        # VirusTotal 雲端查詢（若有 API Key 且未達停止條件）
        if not self.stop_event.is_set() and self.vt_client and self.vt_client.api_key:
            vt_response = self.vt_client.lookup_by_hash(sha256)
            detected, total = VirusTotalClient.parse_detections(vt_response)
            result.vt_detected = detected
            result.vt_total = total

            if result.local_malicious:
                # 已本地命中，維持 Helpme
                result.severity = "Helpme"
            else:
                result.severity = classify_severity(detected, total)
                if result.severity != "Safe":
                    result.status = "threat"

        # 記錄風險檔案
        if result.status == "threat":
            with self._lock:
                self.report.risks.append(result)
                self.report.risk_files += 1

        if self.on_file_scanned:
            self.on_file_scanned(result)

        return result

    def run(self) -> ScanReport:
        """執行完整掃描，回傳 ScanReport。"""
        files = self._collect_files()
        self.report.total_files = len(files)

        for file_path in files:
            if self.stop_event.is_set():
                break

            self._scan_single(file_path)
            with self._lock:
                self.report.scanned_files += 1

        self.report.finished_at = format_timestamp()
        start = datetime.strptime(self.report.started_at, "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(self.report.finished_at, "%Y-%m-%d %H:%M:%S")
        self.report.duration_seconds = (end - start).total_seconds()
        return self.report

    def save_report_json(self, output_path: str) -> None:
        """將報告寫入 JSON 檔案（委派給 ScanReport）。"""
        self.report.save_report_json(output_path)


# ---------------------------------------------------------------------------
# NVIDIA 智慧檢查（僅限 nemotron-3.5-lightning-30b-a3b）
# ---------------------------------------------------------------------------

class NVIDIAClient:
    """NVIDIA NIM API 客戶端，用於智慧威脅分析。

    模型：nvidia/nemotron-3.5-lightning-30b-a3b
    端點：https://integrate.api.nvidia.com/v1/chat/completions
    """

    BASE_URL = "https://integrate.api.nvidia.com/v1"
    MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._lock = threading.Lock()

    def analyze_threat(
        self,
        file_path: str,
        sha256: str,
        vt_detected: int,
        vt_total: int,
        local_malicious: bool,
    ) -> Optional[dict]:
        """呼叫 NVIDIA 模型對單一檔案進行智慧威脅分析。

        回傳：
            解析後的 JSON 字典，包含威脅等級、建議動作與說明；失敗則回傳 None。
        """
        if not self.api_key:
            return None

        self._lock.acquire()
        try:
            prompt = (
                "You are a cybersecurity threat analyst. Analyze the following file scan result "
                "and provide a threat assessment in JSON format only.\n\n"
                f"File path: {file_path}\n"
                f"SHA-256: {sha256}\n"
                f"Local blacklist hit: {local_malicious}\n"
                f"VirusTotal detections: {vt_detected}/{vt_total}\n\n"
                "Reply with exactly this JSON structure:\n"
                '{"threat_level": "Safe|Low|Medium|High|Critical", '
                '"confidence": 0-100, '
                '"recommended_action": "ignore|quarantine|delete|scan_full_system", '
                '"reasoning": "brief explanation in Traditional Chinese"}\n'
                "Do not include any text outside the JSON."
            )

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            payload = {
                "model": self.MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 512,
            }

            try:
                resp = requests.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    # 嘗試解析 JSON（模型有時會加上 ```json 標記）
                    content = content.strip()
                    if content.startswith("```"):
                        content = content.split("```")[1]
                        if content.startswith("json"):
                            content = content[4:]
                    return json.loads(content)
                return None
            except Exception:
                return None
        finally:
            self._lock.release()


class SmartScanner(Scanner):
    """擴展掃描器，加入 NVIDIA 智慧威脅檢查。"""

    def __init__(self, *args, nvidia_client: Optional[NVIDIAClient] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.nvidia_client = nvidia_client

    def _scan_single(self, file_path: str) -> ScanResult:
        result = super()._scan_single(file_path)

        # 僅對風險檔案或本地黑名單命中檔案進行 NVIDIA 智慧分析
        if (
            self.nvidia_client
            and self.nvidia_client.api_key
            and (result.status == "threat" or result.local_malicious)
        ):
            ai_result = self.nvidia_client.analyze_threat(
                file_path=result.path,
                sha256=result.sha256,
                vt_detected=result.vt_detected,
                vt_total=result.vt_total,
                local_malicious=result.local_malicious,
            )
            if ai_result:
                result.ai_threat_level = ai_result.get("threat_level", "Unknown")
                result.ai_confidence = ai_result.get("confidence", 0)
                result.ai_action = ai_result.get("recommended_action", "ignore")
                result.ai_reasoning = ai_result.get("reasoning", "")

                # 如果 AI 判定為 Critical，升級為 Helpme
                if result.ai_threat_level == "Critical":
                    result.severity = "Helpme"

        return result


# ---------------------------------------------------------------------------
# 隔離區（Quarantine）
# ---------------------------------------------------------------------------

class Quarantine:
    """將風險檔案移至安全的隔離資料夾，並記錄 manifest 以供還原。"""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.join(os.getcwd(), "quarantine")
        os.makedirs(self.base_dir, exist_ok=True)
        self.manifest_path = os.path.join(self.base_dir, "manifest.json")

    def _load_manifest(self) -> list[dict]:
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

    def _save_manifest(self, items: list[dict]) -> None:
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)

    def move_to_quarantine(self, file_path: str, sha256: str = "") -> dict:
        """將檔案移入隔離區。回傳操作結果。"""
        import shutil

        try:
            if not os.path.exists(file_path):
                return {"ok": False, "error": "檔案不存在"}

            name = os.path.basename(file_path)
            stamped = f"{int(time.time())}_{name}"
            dest = os.path.join(self.base_dir, stamped)

            # 避免撞名
            i = 1
            while os.path.exists(dest):
                stamped = f"{int(time.time())}_{i}_{name}"
                dest = os.path.join(self.base_dir, stamped)
                i += 1

            shutil.move(file_path, dest)

            items = self._load_manifest()
            entry = {
                "quarantined_name": stamped,
                "original_path": file_path,
                "sha256": sha256,
                "quarantined_at": format_timestamp(),
            }
            items.append(entry)
            self._save_manifest(items)
            return {"ok": True, "entry": entry}
        except (OSError, PermissionError) as exc:
            return {"ok": False, "error": str(exc)}

    def restore(self, quarantined_name: str) -> dict:
        """將隔離檔案還原至原始路徑。"""
        import shutil

        items = self._load_manifest()
        entry = next((e for e in items if e["quarantined_name"] == quarantined_name), None)
        if not entry:
            return {"ok": False, "error": "找不到隔離記錄"}

        src = os.path.join(self.base_dir, quarantined_name)
        try:
            os.makedirs(os.path.dirname(entry["original_path"]), exist_ok=True)
            shutil.move(src, entry["original_path"])
            self._save_manifest([e for e in items if e["quarantined_name"] != quarantined_name])
            return {"ok": True}
        except (OSError, PermissionError) as exc:
            return {"ok": False, "error": str(exc)}

    def delete_permanently(self, quarantined_name: str) -> dict:
        """永久刪除隔離區中的檔案。"""
        items = self._load_manifest()
        entry = next((e for e in items if e["quarantined_name"] == quarantined_name), None)
        if not entry:
            return {"ok": False, "error": "找不到隔離記錄"}

        src = os.path.join(self.base_dir, quarantined_name)
        try:
            if os.path.exists(src):
                os.remove(src)
            self._save_manifest([e for e in items if e["quarantined_name"] != quarantined_name])
            return {"ok": True}
        except (OSError, PermissionError) as exc:
            return {"ok": False, "error": str(exc)}

    def list_all(self) -> list[dict]:
        """列出所有隔離記錄。"""
        return self._load_manifest()


# ---------------------------------------------------------------------------
# 掃描歷史（History）
# ---------------------------------------------------------------------------

class HistoryManager:
    """管理掃描歷史記錄（history.json）。"""

    MAX_ENTRIES = 50

    def __init__(self, base_dir: Optional[str] = None):
        self.file_path = os.path.join(base_dir or os.getcwd(), "history.json")

    def append(self, report: ScanReport, mode: str = "full") -> dict:
        """新增一筆掃描歷史。"""
        items = self.list_all()
        entry = {
            "id": int(time.time()),
            "target_folder": report.target_folder,
            "mode": mode,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "total_files": report.total_files,
            "scanned_files": report.scanned_files,
            "risk_files": report.risk_files,
            "error_files": report.error_files,
            "duration_seconds": round(report.duration_seconds, 2),
        }
        items.insert(0, entry)
        items = items[: self.MAX_ENTRIES]
        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(items, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
        return entry

    def list_all(self) -> list[dict]:
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
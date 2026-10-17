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

    def __init__(
        self,
        target_folder: str,
        blacklist: Optional[Blacklist] = None,
        vt_client: Optional[VirusTotalClient] = None,
        on_file_scanned: Optional[Callable[[ScanResult], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ):
        self.target_folder = os.path.abspath(target_folder)
        self.blacklist = blacklist or Blacklist()
        self.vt_client = vt_client
        self.on_file_scanned = on_file_scanned
        self.stop_event = stop_event or threading.Event()

        self.report = ScanReport(
            target_folder=self.target_folder,
            started_at=format_timestamp(),
        )
        self._lock = threading.Lock()

    def stop(self) -> None:
        self.stop_event.set()

    def _collect_files(self) -> list[str]:
        """遞迴蒐集所有檔案路徑。"""
        files: list[str] = []
        for root, _dirs, filenames in os.walk(self.target_folder):
            for name in filenames:
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
        """將報告寫入 JSON 檔案。"""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.report.to_dict(), f, ensure_ascii=False, indent=2)
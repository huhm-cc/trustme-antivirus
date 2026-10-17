"""TrustmeAntivirus 工具模組：檔案雜湊計算與日誌格式化."""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from datetime import datetime
from typing import Optional


def compute_sha256(file_path: str) -> Optional[str]:
    """計算指定檔案的 SHA-256 雜湊值。

    參數：
        file_path: 目標檔案絕對路徑。

    回傳：
        SHA-256 十六進位字串；若讀取失敗（權限不足、檔案被鎖定等）
        則回傳 None，並不會拋出例外中斷掃描流程。
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError, FileNotFoundError) as exc:
        logging.debug("無法計算雜湊 %s: %s", file_path, exc)
        return None


def format_timestamp() -> str:
    """回傳目前時間的 ISO 8601 字串，供日誌與報告使用。"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def classify_severity(detection_count: int, total_engines: int) -> str:
    """根據 VirusTotal 偵測數量分類嚴重程度。

    參數：
        detection_count: 標記為惡意的引擎數量。
        total_engines: 總參與掃描的引擎數量。

    回傳：
        "Low" / "Medium" / "High" / "Helpme" / "Safe"
    """
    if detection_count == 0:
        return "Safe"

    ratio = detection_count / max(total_engines, 1)

    if detection_count >= 40 or ratio >= 0.5:
        return "Helpme"
    if detection_count >= 15 or ratio >= 0.25:
        return "High"
    if detection_count >= 5 or ratio >= 0.1:
        return "Medium"
    return "Low"


def setup_logging(log_file: Optional[str] = None, level: int = logging.INFO) -> None:
    """初始化全域日誌設定。

    參數：
        log_file: 若提供，同時寫入檔案；否則僅輸出至 stdout。
        level: 日誌層級。
    """
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True,
    )


def get_resource_path(relative_path: str) -> str:
    """取得打包後執行檔內的資源絕對路徑（PyInstaller 一檔案模式專用）。

    未打包時回傳專案根目錄下的相對路徑；打包後回傳 sys._MEIPASS 下的路徑。
    """
    try:
        base_path = sys._MEIPASS  # type: ignore[attr-defined]
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
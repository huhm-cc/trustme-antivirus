"""TrustmeAntivirus 程式進入點（pywebview + HTML/CSS 前端）。

啟動 WebView 視窗並載入 src/web/index.html 界面，
後端 API 由 src/api.py 的 BridgeAPI 提供。
"""

from __future__ import annotations

import sys
import os

# 確保可直接以 python src/main.py 執行時，正確匯入 src 套件
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api import BridgeAPI  # noqa: E402
import webview  # noqa: E402


def get_base_dir() -> str:
    """取得資料儲存目錄。

    開發模式：專案根目錄。
    Nuitka onefile：寫入 %APPDATA%/TrustmeAntivirus（onefile 每次解壓到
    不同臨時目錄，資料必須存持久位置）。
    """
    if getattr(sys, "frozen", False):
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(appdata, "TrustmeAntivirus")
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    api = BridgeAPI(base_dir=get_base_dir())

    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "index.html")

    webview.create_window(
        "TrustmeAntivirus - 系統安全防禦",
        html_path,
        js_api=api,
        width=1100,
        height=720,
        min_size=(900, 600),
    )
    webview.start()


if __name__ == "__main__":
    main()
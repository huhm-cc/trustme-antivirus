"""TrustmeAntivirus 程式進入點。

啟動 Tkinter 圖形介面與掃描引擎。
"""

from __future__ import annotations

import sys
import os

# 確保可直接以 python src/main.py 執行時，正確匯入 src 套件
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gui import TrustmeAntivirusGUI  # noqa: E402
import tkinter as tk  # noqa: E402


def main() -> None:
    # 啟用 Windows 高 DPI 感知，避免系統點陣縮放導致介面模糊
    if sys.platform == "win32":
        import ctypes

        try:
            # Per-Monitor V2（Windows 10 1703+ 最佳清晰度）
            ctypes.windll.user32.SetProcessDpiAwarenessContext(
                ctypes.c_void_p(-4)
            )
        except Exception:
            try:
                # 舊版 Windows 退回 System DPI 感知
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass

    root = tk.Tk()
    app = TrustmeAntivirusGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
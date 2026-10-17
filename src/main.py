"""TrustmeAntivirus 程式進入點。

啟動 CustomTkinter 圖形介面與掃描引擎。
CustomTkinter 會自動啟用 Windows 高 DPI 感知，介面不會模糊。
"""

from __future__ import annotations

import sys
import os

# 確保可直接以 python src/main.py 執行時，正確匯入 src 套件
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gui import TrustmeAntivirusGUI  # noqa: E402
import customtkinter as ctk  # noqa: E402


def main() -> None:
    root = ctk.CTk()
    app = TrustmeAntivirusGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
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
    root = tk.Tk()
    app = TrustmeAntivirusGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
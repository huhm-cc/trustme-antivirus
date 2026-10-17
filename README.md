# TrustmeAntivirus

> **Trust me, Your System is Safe.**

TrustmeAntivirus 是一款輕量、開源、0 成本的 Windows 桌面防毒與檔案掃描工具，結合本地 SHA-256 雜湊黑名單與免費 VirusTotal 雲端 API 檢測，使用 Python 與 Tkinter 開發，可打包為單一 `.exe` 執行檔。

## 專案目標

打造一套無需商業授權、程式碼公開透明的個人級防毒掃描工具，適合：
- 個人使用者快速掃描指定資料夾
- 開源社群自行維護本地病毒碼黑名單
- 搭配免費 VirusTotal API 進行雲端二次驗證

## 功能特色

- 📁 **遞迴資料夾掃描**：支援選擇任意目標資料夾，遞迴掃描其中所有檔案
- 🔐 **本地 SHA-256 黑名單**：內建 `Blacklist` HashSet，支援外部 `blacklist.txt` / `blacklist.json` 載入
- ☁️ **VirusTotal API v3 查詢**：傳入檔案雜湊檢查惡意評分，內建免費 API 速率限制（每分鐘 4 次請求）
- ⚠️ **風險等級分類**：Low / Medium / High / Helpme，Medium 以上彈出提醒，Helpme 標示劇烈病毒
- 🖥️ **Tkinter 現代 GUI**：亮色與暗黑主題切換、進度條、即時 ScrolledText 日誌
- 🧵 **多執行緒掃描**：掃描期間介面不會凍結
- 📦 **單一 .exe 打包**：PyInstaller `--onefile --noconsole`，無需安裝 Python 環境即可執行

## 目錄結構

```
TrustmeAntivirus/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── workflows/
│       └── build.yml
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── scanner.py
│   ├── gui.py
│   └── utils.py
├── .gitignore
├── LICENSE
├── SECURITY.md
├── requirements.txt
└── README.md
```

## 安裝與執行

### 從原始碼執行（開發者）

```powershell
# 克隆專案
git clone https://github.com/illusd/trustme-antivirus.git
cd trustme-antivirus

# 建立虛擬環境並安裝依賴
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 執行程式
python src/main.py
```

### 從 Release 下載 .exe（使用者）

1. 前往 [Releases 頁面](https://github.com/illusd/trustme-antivirus/releases)
2. 下載最新的 `TrustmeAntivirus.exe`
3. 雙擊執行即可

> 注意：由於本專案未購買商業數位簽章，Windows SmartScreen 可能顯示警告，請參見下方說明。

## 設定 VirusTotal API（選用）

若要啟用雲端查詢，請設定環境變數：

```powershell
$env:VIRUSTOTAL_API_KEY="你的 API Key"
python src/main.py
```

免費 API 每分鐘限 4 次請求，程式已自動控制請求間隔，不會超過限額。

## 本地黑名單

在專案根目錄放置 `blacklist.txt`（每行一個 SHA-256）或 `blacklist.json`（`{"hashes": [...]}`），程式啟動時會自動載入。

## Windows SmartScreen 說明（重要）

打包後的 `.exe` **未購買商業數位簽章 (Code Signing Certificate)**，因此首次執行時 Windows SmartScreen 可能顯示：

> 「Windows 保護您的電腦」 / 「Windows 已保護您的電腦」

這並不代表程式含有病毒，而是因為簽章缺失所導致的誤報。若您信任此來源，請依以下步驟執行：

1. 在警告視窗點擊 **「其他資訊」(More info)**
2. 點擊 **「仍要執行」(Run anyway)**

開源社群可自行檢視原始碼並編譯，以確保安全。

## 打包為 .exe

```powershell
pip install pyinstaller
pyinstaller --onefile --noconsole --name TrustmeAntivirus --version-file file_version_info.txt src/main.py
```

產出檔案位於 `dist/TrustmeAntivirus.exe`，內嵌產品名稱 `TrustmeAntivirus` 與版本 `1.0.0.0`。

若有圖示或設定檔，請修改 `TrustmeAntivirus.spec` 的 `datas` 參數，並在程式中以 `sys._MEIPASS` 存取資源。

## 授權

本專案採用 [AGPL License](LICENSE)

## 資安回報

請參見 [SECURITY.md](SECURITY.md)。

## 貢獻

歡迎提交 Issue 與 Pull Request，共同改進 TrustmeAntivirus。

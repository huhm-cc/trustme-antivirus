# TrustmeAntivirus

> **Trust me, Your System is Safe.**

TrustmeAntivirus 是一款輕量、開源、0 成本的 Windows 桌面防毒與檔案掃描工具，結合本地 SHA-256 雜湊黑名單、VirusTotal 雲端 API 與 NVIDIA AI 智慧檢查，使用 pywebview + HTML/CSS 打造現代界面，並以 Nuitka 打包為單一 `.exe`。

## 專案目標

打造一套無需商業授權、程式碼公開透明的個人級防毒掃描工具，適合：
- 個人使用者快速掃描指定資料夾
- 開源社群自行維護本地病毒碼黑名單
- 搭配免費 VirusTotal API 與 NVIDIA AI 進行雲端二次驗證

## 技術棧

- **後端**：Python 3.x + requests
- **界面**：pywebview + HTML / CSS / JavaScript（單檔式 SPA）
- **AI**：NVIDIA NIM API（模型：`nvidia/nemotron-3.5-lightning-30b-a3b`）
- **打包**：Nuitka（onefile 單一執行檔）

## 功能特色

- 📁 **遞迴資料夾掃描**：完整掃描（所有檔案）或快速掃描（僅可執行檔/指令碼）
- 🔐 **本地 SHA-256 黑名單**：支援外部 `blacklist.txt` / `blacklist.json`
- ☁️ **VirusTotal API v3**：雲端惡意評分查詢，內建免費版速率限制（每分鐘 4 次）
- 🤖 **NVIDIA AI 智慧檢查**：對風險檔案進行 AI 威脅分析（等級、信心度、建議動作、中文說明）
- ⚠️ **風險等級分類**：Low / Medium / High / Helpme
- 🛡️ **自動背景檢查**：可設定間隔，定期自動快速掃描上次目標資料夾
- 🚧 **隔離區**：將風險檔案安全移入隔離資料夾，可還原或永久刪除
- 📜 **掃描歷史記錄**：自動保存最近 50 次掃描摘要
- 📊 **儀表板**：即時統計卡片 + 系統資訊面板
- 🎨 **深色 / 淺色主題**：一鍵切換
- 📤 **報告匯出**：JSON + CSV 雙格式
- ✨ **現代界面**：玻璃擬態、漸變動畫進度條、Toast 通知

## 目錄結構

```
TrustmeAntivirus/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── workflows/
│       └── build.yml          # 推 tag 自動以 Nuitka 打包
├── src/
│   ├── __init__.py
│   ├── main.py                # pywebview 入口
│   ├── api.py                 # JS↔Python 橋接 API
│   ├── scanner.py             # 掃描引擎 / 隔離區 / 歷史
│   └── utils.py               # 雜湊 / 系統資訊 / 工具
│   └── web/
│       ├── index.html         # 界面
│       ├── style.css          # 樣式與動畫
│       └── app.js             # 前端邏輯
├── file_version_info.txt
├── .gitignore
├── LICENSE
├── SECURITY.md
├── requirements.txt
└── README.md
```

## 安裝與執行

### 從原始碼執行（開發者）

```powershell
git clone https://github.com/illusd/trustme-antivirus.git
cd trustme-antivirus

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python src/main.py
```

> 需要 Microsoft WebView2 Runtime（Windows 10/11 通常已內建）。

### 從 Release 下載 .exe（使用者）

1. 前往 [Releases 頁面](https://github.com/illusd/trustme-antivirus/releases)
2. 下載最新的 `TrustmeAntivirus.exe`
3. 雙擊執行即可

## API 金鑰設定（選用）

| 環境變數 | 用途 |
|----------|------|
| `VIRUSTOTAL_API_KEY` | 啟用 VirusTotal 雲端查詢 |
| `NVIDIA_API_KEY` | 啟用 NVIDIA AI 智慧檢查（`nvidia/nemotron-3.5-lightning-30b-a3b`，端點 `https://integrate.api.nvidia.com/v1`） |

```powershell
$env:VIRUSTOTAL_API_KEY="你的 Key"
$env:NVIDIA_API_KEY="你的 Key"
python src/main.py
```

## Nuitka 打包

```powershell
pip install -r requirements.txt
python -m nuitka --onefile --windows-disable-console --enable-plugin=tkinter --assume-yes-for-downloads --include-data-dir=src/web=web --output-dir=dist --output-filename=TrustmeAntivirus.exe src/main.py
```

產出：`dist/TrustmeAntivirus.exe`

> 首次編譯會自動下載 MinGW64 編譯器，需較長時間；之後有快取會快很多。

## Windows SmartScreen 說明（重要）

打包後的 `.exe` **未購買商業數位簽章**，首次執行時 Windows SmartScreen 可能顯示「Windows 已保護您的電腦」。

這不代表程式含有病毒，而是簽章缺失導致的誤報。若您信任此來源：

1. 點擊 **「其他資訊」(More info)**
2. 點擊 **「仍要執行」(Run anyway)**

開源社群可自行檢視原始碼並編譯，以確保安全。

## 授權

本專案採用 [AGPL License](LICENSE)

## 資安回報

請參見 [SECURITY.md](SECURITY.md)。

## 貢獻

歡迎提交 Issue 與 Pull Request，共同改進 TrustmeAntivirus。

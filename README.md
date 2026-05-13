# FortiGate Auto-Ban System

自動化安全防禦系統，整合 FortiGate 防火牆 REST API 與 Telegram Bot，實現即時威脅偵測與自動封鎖。

---

## 系統概述

當攻擊者對 FortiGate 防火牆發動暴力破解攻擊時，系統自動完成以下流程：

```
攻擊者登入失敗
    → FortiGate 發送 Syslog
    → 系統解析並統計失敗次數
    → 達到閾值（預設 3 次 / 10 分鐘）
    → 自動呼叫 FortiGate API 封鎖 IP
    → Telegram 即時通知管理員
```

管理員可透過 Telegram Bot 指令查詢黑名單、手動解封，無需登入防火牆管理介面。

---

## 功能特點

- **自動封鎖**：偵測暴力破解，達到閾值自動封鎖攻擊者 IP
- **即時通知**：封鎖事件透過 Telegram 推送給管理員
- **遠端管理**：透過 Telegram Bot 指令查詢、解封黑名單
- **白名單機制**：支援單一 IP 與 CIDR 格式，防止誤封
- **封鎖佇列**：asyncio Queue 序列化 API 呼叫，避免並發衝突
- **記憶體防護**：定期清理過期計數器，防止記憶體洩漏
- **Mock 模式**：開發測試時不會真的呼叫 FortiGate API

---

## 技術架構

三大模組獨立設計，透過 `main.py` 整合：

| 模組 | 檔案 | 職責 |
|------|------|------|
| FortiGate Client | `fortigate_client.py` | 封裝 FortiGate REST API |
| Syslog Processor | `syslog_processor.py` | 接收 UDP Syslog、解析、計數、觸發封鎖 |
| Telegram Bot | `telegram_bot.py` | 管理介面與即時通知 |

**技術棧**

| 技術 | 用途 |
|------|------|
| Python 3.10+ / AsyncIO | 非同步事件處理 |
| httpx | FortiGate REST API 呼叫 |
| python-telegram-bot 20.7 | Telegram Bot 框架 |
| Docker / docker-compose | 容器化部署 |

詳細架構說明請見 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## 快速開始

### 1. 環境需求

- Python 3.10+
- FortiGate 防火牆（具備 API 存取權限）
- Telegram Bot Token（透過 @BotFather 建立）

### 2. 安裝依賴

```bash
cd scripts/security_TG_BOT
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate

pip install -r ../../requirements.txt
```

### 3. 設定環境變數

```bash
cp scripts/.env.example scripts/.env
```

編輯 `scripts/.env`：

```bash
# FortiGate 設定
FORTIGATE_HOST=your.fortigate.ip
FORTIGATE_TOKEN=your_api_token_here

# Telegram 設定
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_ADMIN_IDS=your_user_id
TELEGRAM_CHAT_ID=your_chat_id

# 系統設定
USE_REAL_FORTIGATE=false    # true = 真實封鎖，false = 安全測試模式
FAIL_THRESHOLD=3             # 失敗次數閾值
TIME_WINDOW=600              # 時間窗口（秒）
WHITELIST=10.0.0.0/8         # 白名單（逗號分隔）
```

### 4. 執行

```bash
cd scripts/security_TG_BOT
.venv/Scripts/python main.py
```

---

## FortiGate 設定

### Syslog 設定

在 FortiGate CLI 執行：

```
config log syslogd setting
    set status enable
    set server "你的伺服器IP"
    set port 5141
    set mode udp
end
```

### Firewall Policy

建立封鎖規則（將 `ban_list` Address Group 設為拒絕）：

```
config firewall policy
    edit 10
        set name "Auto-Ban-Policy"
        set srcaddr "ban_list"
        set action deny
    next
end
```

詳細設定步驟請見 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

---

## Docker 部署

```bash
# 複製並設定環境變數
cp scripts/.env.example scripts/.env
# 編輯 scripts/.env ...

# 啟動
docker-compose up -d

# 查看日誌
docker logs -f fortigate-autoban
```

---

## Telegram Bot 指令

| 指令 | 權限 | 功能 |
|------|------|------|
| `/start` | 所有人 | 顯示說明 |
| `/list` | 所有人 | 列出黑名單 IP |
| `/stats` | 所有人 | 顯示統計資料 |
| `/status` | 所有人 | 系統狀態 |
| `/unban <IP>` | 管理員 | 解除封鎖 |
| `/test <IP>` | 管理員 | 測試通知功能 |

---

## 專案結構

```
security_TG_BOT/
├── scripts/
│   ├── .env.example              # 環境變數範本
│   └── security_TG_BOT/
│       ├── main.py               # 主程式（系統整合）
│       ├── fortigate_client.py   # FortiGate API Client
│       ├── syslog_processor.py   # Syslog 處理器
│       └── telegram_bot.py       # Telegram Bot
├── docs/
│   ├── ARCHITECTURE.md           # 系統架構說明
│   ├── DEPLOYMENT.md             # 部署指南
│   └── SECURITY-REVIEW-2026-02-07.md  # 安全性審查報告
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── SDD.md                        # 系統設計文件
```

---

## 安全性說明

本系統的安全性審查報告見 [docs/SECURITY-REVIEW-2026-02-07.md](docs/SECURITY-REVIEW-2026-02-07.md)，識別並記錄了已知風險與對應的緩解措施。

生產環境部署前建議：
- 啟用 SSL 憑證驗證（或使用 CA 簽發憑證）
- 設定 FortiGate API `trusthost`，限制 API 來源 IP
- 確認 Telegram Admin IDs 只包含授權管理員

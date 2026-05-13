# FortiGate Auto-Ban System - 系統架構文件

本文件說明 FortiGate Auto-Ban System 的完整架構、模組設計、API 串接方式與運作流程。

**文件版本**: 1.2
**最後更新**: 2026-02-13

---

## 📋 目錄

1. [系統概述](#1-系統概述)
2. [系統架構](#2-系統架構)
3. [核心模組詳解](#3-核心模組詳解)
4. [資料流程](#4-資料流程)
5. [API 串接說明](#5-api-串接說明)
   - 5.1 FortiGate REST API（Token 認證、封鎖/解封完整流程、curl 重現）
   - 5.2 Telegram Bot API（Long Polling、getUpdates、sendMessage）
   - 5.3 Syslog 協定（UDP 接收、格式解析、netcat 重現）
6. [配置說明](#6-配置說明)
7. [程式碼結構](#7-程式碼結構)

---

## 1. 系統概述

### 1.1 系統目的

FortiGate Auto-Ban System 是一個自動化安全防護系統，用於：
- 即時監控 FortiGate 防火牆的登入失敗事件
- 自動統計攻擊者 IP 的失敗次數
- 達到閾值時自動封鎖惡意 IP
- 透過 Telegram 即時通知管理員

### 1.2 核心功能

| 功能 | 說明 |
|------|------|
| **Syslog 監聽** | 接收 FortiGate 發送的 Syslog 訊息（UDP 5141） |
| **事件解析** | 解析登入失敗事件，提取攻擊者 IP |
| **失敗計數** | 統計時間窗口內的失敗次數 |
| **自動封鎖** | 達到閾值自動呼叫 FortiGate API 封鎖 IP |
| **Telegram 通知** | 即時發送封鎖通知給管理員 |
| **遠端管理** | 透過 Telegram Bot 查詢與管理黑名單 |

### 1.3 技術棧

| 技術 | 版本 | 用途 |
|------|------|------|
| **Python** | 3.10+ | 主要開發語言 |
| **AsyncIO** | 內建 | 非同步事件處理 |
| **httpx** | 0.25.2 | HTTP Client（FortiGate API） |
| **python-telegram-bot** | 20.7 | Telegram Bot 框架 |
| **python-dotenv** | 1.0.0 | 環境變數管理 |
| **Docker** | 20.10+ | 容器化部署 |

---

## 2. 系統架構

### 2.1 整體架構圖

```
┌──────────────────────────────────────────────────────────────────┐
│                    FortiGate Auto-Ban System                     │
└──────────────────────────────────────────────────────────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                │                 │                 │
                ▼                 ▼                 ▼
        ┌───────────────┐ ┌──────────────┐ ┌──────────────┐
        │   Syslog      │ │  FortiGate   │ │   Telegram   │
        │  Processor    │ │    Client    │ │     Bot      │
        └───────────────┘ └──────────────┘ └──────────────┘
                │                 │                 │
                └─────────────────┼─────────────────┘
                                  │
                            ┌─────┴─────┐
                            │   main.py │
                            │ (整合層)   │
                            └───────────┘
```

### 2.2 運作流程

```
外部攻擊者
   │ 嘗試登入失敗
   ▼
FortiGate 防火牆
   │ 產生 Syslog
   ▼ UDP 5141
Syslog Processor
   │ 解析 IP、計數
   │ 達到閾值 (3次/10分鐘)
   ▼
FortiGate Client
   │ API: POST /firewall/address
   │ API: PUT /firewall/addrgrp
   ▼
FortiGate 防火牆
   │ 封鎖 IP
   ▼
Telegram Bot
   │ 發送通知
   ▼
管理員手機
```

### 2.3 三大模組關係

```
┌─────────────────────────────────────────────────────────┐
│                      main.py (AutoBanSystem)            │
│  職責：整合三大模組、管理生命週期、協調通訊              │
└─────────────────────────────────────────────────────────┘
         │                    │                    │
         │ 建立實例           │ 建立實例           │ 建立實例
         ▼                    ▼                    ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ SyslogProcessor  │  │ FortiGateClient  │  │   SecurityBot    │
│ (事件處理)        │  │ (API 操作)        │  │ (通知與管理)      │
└──────────────────┘  └──────────────────┘  └──────────────────┘
         │                    ▲                    ▲
         │ 觸發封鎖            │ 呼叫 API            │ 發送通知
         └────────────────────┴────────────────────┘
              self.fortigate.block_ip()
              self.notifier(ip, count, ...)
```

---

## 3. 核心模組詳解

### 3.1 Syslog Processor (syslog_processor.py)

#### 3.1.1 模組職責

- 啟動 UDP Server 監聽 Syslog（預設 port 5141）
- 解析 FortiGate Syslog 訊息，提取攻擊者 IP
- 維護失敗計數器（時間窗口內）
- 達到閾值時將 IP 加入封鎖佇列（Ban Queue）
- 單一 Worker 依序執行 FortiGate API 呼叫（避免並發 HTTP 500）
- 支援白名單功能（單一 IP 及 CIDR 網段格式）
- 每小時定期清理失效計數紀錄，防止記憶體洩漏

#### 3.1.2 核心類別

**SyslogProcessor**

```python
class SyslogProcessor:
    def __init__(
        self,
        fortigate_client,      # FortiGate API Client 實例
        notifier: Callable,     # 通知函數
        threshold: int = 3,     # 失敗次數閾值
        time_window: int = 600, # 時間窗口（秒）
        whitelist: list = None  # 白名單 IP
    )
```

#### 3.1.3 主要方法

| 方法 | 說明 |
|------|------|
| `start_server(host, port)` | 啟動 UDP Server、Ban Queue Worker 及定期清理任務 |
| `stop_server()` | 停止 UDP Server、Worker 及清理任務 |
| `handle_syslog(message, addr)` | 處理收到的 Syslog 訊息 |
| `_parse_ip_from_syslog(message)` | 從 Syslog 解析攻擊者 IP |
| `_is_whitelisted(ip)` | 檢查 IP 是否在白名單（支援 CIDR） |
| `_is_valid_ip(ip)` | 驗證 IP 格式（使用 ipaddress 模組） |
| `_auto_ban(ip, count)` | 將 IP 加入 Ban Queue |
| `_ban_worker()` | 從 Ban Queue 依序呼叫 FortiGate API |
| `_periodic_cleanup()` | 每小時清理過期計數紀錄 |

#### 3.1.4 資料結構

```python
# 失敗計數器（IP -> 時間戳列表）
failure_counter = {
    "192.168.1.100": [
        datetime(2026, 2, 9, 10, 30, 0),
        datetime(2026, 2, 9, 10, 31, 0),
        datetime(2026, 2, 9, 10, 32, 0)
    ],
    "203.0.113.45": [
        datetime(2026, 2, 9, 10, 35, 0)
    ]
}
max_tracked_ips = 10000  # 最多追蹤 IP 數量上限

# 白名單（分開儲存以利 CIDR 比對）
whitelist_ips = {"192.168.1.1", "10.0.0.1"}        # 單一 IP（set，O(1) 查詢）
whitelist_networks = [IPv4Network("10.0.0.0/8")]    # CIDR 網段（list）

# 封鎖佇列（Ban Queue）
ban_queue = asyncio.Queue()   # IP 待封鎖佇列
banning_ips = set()           # 正在處理中的 IP（防止重複加入）
```

#### 3.1.5 Syslog 解析邏輯

支援多種 FortiGate Syslog 格式：

**格式 1: VPN 登入失敗**
```
<134>date=2026-02-09 time=10:30:45 ... subtype="vpn" action="ssl-login-fail" remip=192.168.1.100 user="testuser" msg="SSL VPN login fail"
```
提取關鍵字：`remip=` 或 `srcip=`

**格式 2: SSH/管理介面登入失敗**
```
<133>date=2026-02-09 time=10:31:20 ... subtype="system" action="login" status="failed" srcip=192.168.1.100 msg="Admin login failed"
```
提取關鍵字：`srcip=` 或 `src=`

**格式 3: 防火牆阻擋**
```
<134>date=2026-02-09 time=10:33:00 ... type="traffic" action="deny" srcip=192.168.1.100 dstip=...
```
提取關鍵字：`srcip=`

#### 3.1.6 時間窗口計數機制

```python
# 範例：threshold=3, time_window=600 (10分鐘)

時間軸：
10:30:00  第1次失敗  [記錄時間戳]
10:31:00  第2次失敗  [記錄時間戳]
10:32:00  第3次失敗  [記錄時間戳] → 達到閾值 → 觸發封鎖

10:42:00  第4次失敗  [清理 10:32:00 之前的記錄] → count=1 (未達閾值)
```

---

### 3.2 FortiGate Client (fortigate_client.py)

#### 3.2.1 模組職責

- 封裝 FortiGate REST API 操作
- 提供 IP 封鎖/解封的高階介面
- 管理 Address 物件和 Address Group
- 處理 API 錯誤與重試

#### 3.2.2 核心類別

**FortiGateClient**

```python
class FortiGateClient:
    def __init__(
        self,
        host: str = None,   # FortiGate IP/域名
        token: str = None   # API Token
    )
```

#### 3.2.3 主要方法

| 方法 | 說明 | HTTP 請求 |
|------|------|----------|
| `block_ip(ip, comment)` | 封鎖 IP | POST + PUT |
| `unblock_ip(ip)` | 解除封鎖 | DELETE + PUT |
| `list_banned_ips()` | 列出所有封鎖的 IP | GET |
| `get_ip_info(ip)` | 取得 IP 詳細資訊 | GET |
| `is_ip_blocked(ip)` | 檢查 IP 是否已封鎖 | GET |
| `close()` | 關閉 HTTP 連線 | - |

#### 3.2.4 封鎖流程 (block_ip)

```python
async def block_ip(self, ip: str, comment: str) -> bool:
    """
    封鎖流程：
    1. 建立 Address 物件（name: ban_192_168_1_100, subnet: 192.168.1.100/32）
    2. 檢查 ban_list Address Group 是否存在
    3. 如果不存在，建立 ban_list Group
    4. 將 Address 加入 ban_list Group

    FortiGate 端需要有對應的 Firewall Policy:
    - Source: ban_list
    - Action: DENY
    """
```

**API 呼叫順序**：

```
1. POST /api/v2/cmdb/firewall/address
   Body: {
       "name": "ban_192_168_1_100",
       "subnet": "192.168.1.100 255.255.255.255",
       "comment": "Auto-banned: 3 failed login attempts"
   }

2. GET /api/v2/cmdb/firewall/addrgrp/ban_list
   (檢查 ban_list 是否存在)

3. PUT /api/v2/cmdb/firewall/addrgrp/ban_list
   Body: {
       "member": [
           {"name": "ban_192_168_1_100"},
           {"name": "ban_203_0_113_45"},
           ...
       ]
   }
```

#### 3.2.5 解封流程 (unblock_ip)

```
1. GET /api/v2/cmdb/firewall/addrgrp/ban_list
   (取得當前 members)

2. PUT /api/v2/cmdb/firewall/addrgrp/ban_list
   (移除指定 IP 的 member)

3. DELETE /api/v2/cmdb/firewall/address/ban_192_168_1_100
   (刪除 Address 物件)
```

---

### 3.3 Telegram Bot (telegram_bot.py)

#### 3.3.1 模組職責

- 提供 Telegram Bot 管理介面
- 接收與發送 Telegram 訊息
- 執行管理指令（查詢、解封）
- 發送自動封鎖通知

#### 3.3.2 核心類別

**SecurityBot**

```python
class SecurityBot:
    def __init__(
        self,
        token: str,             # Bot Token
        admin_ids: List[int],   # 管理員 User ID 列表
        fortigate_client        # FortiGate Client 實例
    )
```

#### 3.3.3 Telegram 指令

| 指令 | 權限 | 功能 | 回應範例 |
|------|------|------|---------|
| `/start` | 所有人 | 顯示歡迎訊息與指令說明 | 功能清單 |
| `/list` | 所有人 | 列出所有黑名單 IP | IP 清單 |
| `/stats` | 所有人 | 顯示系統統計資料 | 封鎖數、運行時間 |
| `/status` | 所有人 | 顯示系統狀態 | 各元件狀態 |
| `/unban <IP>` | 僅管理員 | 解除指定 IP 的封鎖 | 解封成功/失敗 |
| `/test <IP>` | 僅管理員 | 測試封鎖通知功能 | 測試訊息 |

#### 3.3.4 指令處理流程

```python
使用者發送: /unban 192.168.1.100

1. Telegram Server 發送 Update 給 Bot
   ↓
2. python-telegram-bot 解析指令
   ↓
3. 觸發 cmd_unban() 處理函數
   ↓
4. 檢查權限：is_admin(user_id)
   ├─ 否 → 回應「權限不足」
   └─ 是 → 繼續
   ↓
5. 呼叫 fortigate_client.unblock_ip("192.168.1.100")
   ↓
6. 取得結果
   ├─ 成功 → 回應「已解除封鎖」
   └─ 失敗 → 回應「解封失敗: 原因」
```

#### 3.3.5 自動通知功能

**觸發時機**：Syslog Processor 達到閾值時

**通知內容**：
```
[ALERT] IP 已自動封鎖

IP 位址: 192.168.1.100
失敗次數: 3 次 (10 分鐘內)
來源系統: FortiGate
事件類型: vpn_fail
封鎖時間: 2026-02-09 10:32:00

請使用 /list 查看完整黑名單
```

**實作方式**：
```python
async def send_ban_notification(
    self,
    ip: str,
    fail_count: int,
    source_system: str,
    event_type: str
):
    message = f"""[ALERT] IP 已自動封鎖

IP 位址: {ip}
失敗次數: {fail_count} 次 (10 分鐘內)
來源系統: {source_system}
事件類型: {event_type}
封鎖時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    await self.app.bot.send_message(
        chat_id=self.chat_id,
        text=message
    )
```

---

### 3.4 整合層 (main.py)

#### 3.4.1 模組職責

- 整合三大核心模組
- 管理系統生命週期（啟動、運行、關閉）
- 協調模組間通訊
- 處理信號（SIGINT/SIGTERM）

#### 3.4.2 AutoBanSystem 類別

```python
class AutoBanSystem:
    """
    系統整合類別

    職責：
    1. 初始化三大模組
    2. 建立模組間依賴關係
    3. 協調啟動順序
    4. 提供優雅關閉機制
    """
```

#### 3.4.3 啟動順序

```
1. 載入環境變數 (.env)
   ↓
2. 建立 FortiGate Client (Real or Mock)
   ↓
3. 建立 Telegram Bot
   ├─ 傳入 FortiGate Client（依賴注入）
   └─ 註冊指令 Handler
   ↓
4. 建立 Syslog Processor
   ├─ 傳入 FortiGate Client（依賴注入）
   └─ 傳入 telegram_notification 函數（回調）
   ↓
5. 啟動 Syslog Server (UDP 5141)
   ├─ 啟動 Ban Queue Worker (_ban_worker)
   └─ 啟動定期清理任務 (_periodic_cleanup，每小時執行)
   ↓
6. 啟動 Telegram Bot (非阻塞方式)
   ↓
7. 進入主循環 (while running)
```

#### 3.4.4 模組間依賴

```python
# 依賴關係圖
AutoBanSystem
    ├─ fortigate_client  (獨立，無依賴)
    │
    ├─ telegram_bot
    │   └─> 依賴 fortigate_client (查詢、解封)
    │
    └─ syslog_processor
        ├─> 依賴 fortigate_client (封鎖)
        └─> 依賴 telegram_notification (通知)
```

#### 3.4.5 優雅關閉流程

```
收到 SIGINT/SIGTERM
   ↓
1. 設定 running = False (停止主循環)
   ↓
2. 停止 Telegram Bot
   ├─ app.updater.stop()  (停止接收 Updates)
   ├─ app.stop()          (停止處理)
   └─ app.shutdown()      (釋放資源)
   ↓
3. 停止 Syslog Server
   ├─ transport.close()   (關閉 UDP socket)
   ├─ _worker_task.cancel()   (取消 Ban Queue Worker)
   └─ _cleanup_task.cancel()  (取消定期清理任務)
   ↓
4. 關閉 FortiGate Client
   └─ client.aclose()     (關閉 HTTP 連線)
   ↓
5. 退出程式
```

---

## 4. 資料流程

### 4.1 完整攻擊處理流程

```
[外部攻擊者]
    │ 1. 嘗試登入 FortiGate (VPN/SSH/管理介面)
    │    使用錯誤密碼
    ▼
[FortiGate]
    │ 2. 驗證失敗
    │ 3. 產生 Syslog 訊息
    │    格式: <134>date=... subtype="vpn" action="ssl-login-fail"
    │           remip=192.168.1.100 user="test" msg="..."
    ▼ UDP 5141
[Syslog Processor]
    │ 4. 接收 UDP 封包
    │ 5. 解析 Syslog，提取 IP: 192.168.1.100
    │ 6. 檢查白名單 (如果在白名單，忽略)
    │ 7. 記錄時間戳到 failure_counter[ip]
    │ 8. 清理過期記錄（超過 10 分鐘）
    │ 9. 計算時間窗口內失敗次數
    │    failure_counter["192.168.1.100"] = [10:30, 10:31, 10:32]
    │    count = 3
    │ 10. 判斷: count >= threshold (3) ?
    ├─ 否 → 記錄日誌，等待下次
    └─ 是 → 觸發自動封鎖
    │ 11. 檢查 IP 是否已在 banning_ips（防止重複加入）
    ├─ 是 → 略過（Worker 已在處理）
    └─ 否 → 立刻清空計數器，加入 ban_queue，加入 banning_ips
    ▼
[Ban Queue Worker (_ban_worker)]
    │ (單一 asyncio Worker，確保序列化執行)
    │ 12. 從 queue 取出 IP
    │ 13. 呼叫 block_ip("192.168.1.100", "Auto-ban: 3 failed logins")
    ▼
[FortiGate Client]
    │ 14. POST /api/v2/cmdb/firewall/address
    │     建立 Address: ban_192_168_1_100
    │ 15. PUT /api/v2/cmdb/firewall/addrgrp/ban_list
    │     將 ban_192_168_1_100 加入 ban_list Group
    │ 16. 從 banning_ips 移除該 IP
    ▼
[FortiGate]
    │ 17. 更新防火牆配置
    │ 18. 套用 Policy: Source=ban_list → Action=DENY
    │ 19. 封鎖生效
    ▼
[Ban Queue Worker]
    │ 20. 呼叫 notifier(ip, count, source, event_type)
    ▼
[Telegram Bot]
    │ 21. send_ban_notification()
    │ 22. 呼叫 Telegram API
    ▼
[Telegram Server]
    │ 23. 推送通知給管理員
    ▼
[管理員手機]
    │ 24. 收到通知訊息
    │     [ALERT] IP 已自動封鎖
    │     IP 位址: 192.168.1.100
    │     失敗次數: 3 次...
```

### 4.2 手動解封流程

```
[管理員手機]
    │ 1. 發送指令: /unban 192.168.1.100
    ▼
[Telegram Server]
    │ 2. 轉發 Update 給 Bot
    ▼
[Telegram Bot]
    │ 3. 解析指令，提取 IP
    │ 4. 檢查權限: is_admin(user_id) ?
    ├─ 否 → 回應「權限不足」→ END
    └─ 是 → 繼續
    │ 5. 呼叫 fortigate_client.unblock_ip("192.168.1.100")
    ▼
[FortiGate Client]
    │ 6. GET /api/v2/cmdb/firewall/addrgrp/ban_list
    │    取得當前 members
    │ 7. 移除 ban_192_168_1_100 from members
    │ 8. PUT /api/v2/cmdb/firewall/addrgrp/ban_list
    │    更新 Group members
    │ 9. DELETE /api/v2/cmdb/firewall/address/ban_192_168_1_100
    │    刪除 Address 物件
    ▼
[FortiGate]
    │ 10. 更新防火牆配置
    │ 11. 解封生效
    ▼
[Telegram Bot]
    │ 12. 回應管理員: "已解除 192.168.1.100 的封鎖"
    ▼
[管理員手機]
    │ 13. 收到確認訊息
```

---

## 5. API 串接說明

### 5.1 FortiGate REST API

#### 5.1.1 API 基本資訊

| 項目 | 說明 |
|------|------|
| **Base URL** | `https://{FORTIGATE_HOST}/api/v2/cmdb` |
| **認證方式** | API Token（Bearer Token） |
| **傳輸協定** | HTTPS（SSL 驗證預設關閉，因使用自簽憑證） |
| **資料格式** | JSON |
| **VDOM** | root（預設） |

**必要 Header：**
```
Authorization: Bearer {FORTIGATE_TOKEN}
Content-Type: application/json
```

**SSL 設定**：FortiGate 預設使用自簽憑證，Python 端設定 `verify=False` 並關閉警告：
```python
import httpx, warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
client = httpx.AsyncClient(verify=False)
```

#### 5.1.2 API Token 取得方式

1. 登入 FortiGate GUI → `System` → `Administrators`
2. 選擇 API User（本專案為 `security-bot`）→ `Edit`
3. 點選 `Generate Token`
4. Token 僅顯示一次，立即複製到 `scripts/.env` 的 `FORTIGATE_TOKEN`

Token 限制：
- `security-bot` 帳號設定 `trusthost`，僅允許來自監控伺服器 IP 的 API 呼叫
- 具備 Firewall R/W 權限（`accprofile = super_admin`）

#### 5.1.3 API 端點清單

| 端點 | 方法 | 功能 | 對應程式碼 |
|------|------|------|-----------|
| `/firewall/address` | POST | 建立 Address 物件（單一 IP /32） | `block_ip()` 步驟 1 |
| `/firewall/address/{name}` | GET | 查詢 Address 是否存在 | `is_ip_blocked()` |
| `/firewall/address/{name}` | DELETE | 刪除 Address 物件 | `unblock_ip()` 步驟 3 |
| `/firewall/addrgrp/ban_list` | GET | 查詢 ban_list 群組與成員 | `block_ip()` 步驟 2、`list_banned_ips()` |
| `/firewall/addrgrp/ban_list` | POST | 建立 ban_list 群組（初次） | `block_ip()` 備用路徑 |
| `/firewall/addrgrp/ban_list` | PUT | 更新 ban_list 成員（加入或移除） | `block_ip()` 步驟 3、`unblock_ip()` 步驟 2 |

Address 命名規則：IP `192.168.1.100` → Address 名稱 `ban_192_168_1_100`（`.` 替換為 `_`，加上 `ban_` 前綴）

#### 5.1.4 完整封鎖流程（block_ip）

封鎖一個 IP 需依序呼叫 3 支 API：

**步驟 1 — 建立 Address 物件**

```http
POST https://{FORTIGATE_HOST}/api/v2/cmdb/firewall/address
Authorization: Bearer {FORTIGATE_TOKEN}
Content-Type: application/json

{
    "name": "ban_192_168_1_100",
    "type": "ipmask",
    "subnet": "192.168.1.100 255.255.255.255",
    "comment": "Auto-banned: 3 failed VPN login attempts at 2026-02-13 10:32:00"
}
```

成功回應（HTTP 200）：
```json
{
    "http_method": "POST",
    "results": {"status": "success"},
    "vdom": "root",
    "path": "firewall",
    "name": "address",
    "status": "success",
    "http_status": 200
}
```

失敗情況（IP 已存在，HTTP 500 或 424）：
```json
{
    "http_status": 500,
    "status": "error",
    "error": "Object already exists"
}
```
→ 程式判斷為「已封鎖」，記錄日誌後繼續執行步驟 2。

**步驟 2 — 查詢目前 ban_list 成員**

```http
GET https://{FORTIGATE_HOST}/api/v2/cmdb/firewall/addrgrp/ban_list
Authorization: Bearer {FORTIGATE_TOKEN}
```

成功回應（HTTP 200）：
```json
{
    "http_status": 200,
    "results": [
        {
            "name": "ban_list",
            "member": [
                {"name": "ban_203_0_113_45", "q_origin_key": "ban_203_0_113_45"}
            ],
            "comment": "Auto-ban list managed by security bot"
        }
    ]
}
```

群組不存在（HTTP 404）：
```json
{
    "http_status": 404,
    "status": "error",
    "error": "Entry not found"
}
```
→ 觸發 POST 建立空群組，再繼續步驟 3。

**步驟 3 — 更新 ban_list，加入新成員**

將步驟 2 取得的現有成員加上新 IP，一起 PUT 回去（FortiGate 採全量替換，不支援單筆新增）：

```http
PUT https://{FORTIGATE_HOST}/api/v2/cmdb/firewall/addrgrp/ban_list
Authorization: Bearer {FORTIGATE_TOKEN}
Content-Type: application/json

{
    "member": [
        {"name": "ban_203_0_113_45"},
        {"name": "ban_192_168_1_100"}
    ]
}
```

成功回應（HTTP 200）：
```json
{
    "http_status": 200,
    "status": "success",
    "results": {"status": "success"}
}
```

> **重要**：PUT 必須包含所有現有成員，否則會覆蓋清空。本程式先 GET 取得現有成員清單，append 後再 PUT。

#### 5.1.5 完整解封流程（unblock_ip）

解封需依序呼叫 3 支 API：

**步驟 1 — 查詢 ban_list，取得現有成員**

```http
GET https://{FORTIGATE_HOST}/api/v2/cmdb/firewall/addrgrp/ban_list
Authorization: Bearer {FORTIGATE_TOKEN}
```

回應同 5.1.4 步驟 2。

**步驟 2 — 從 ban_list 移除目標 IP**

將步驟 1 的成員列表去除目標 IP 後，PUT 回去：

```http
PUT https://{FORTIGATE_HOST}/api/v2/cmdb/firewall/addrgrp/ban_list
Authorization: Bearer {FORTIGATE_TOKEN}
Content-Type: application/json

{
    "member": [
        {"name": "ban_203_0_113_45"}
    ]
}
```

（移除 `ban_192_168_1_100`，只剩其他成員）

若解封後 ban_list 為空：
```json
{"member": []}
```

**步驟 3 — 刪除 Address 物件**

```http
DELETE https://{FORTIGATE_HOST}/api/v2/cmdb/firewall/address/ban_192_168_1_100
Authorization: Bearer {FORTIGATE_TOKEN}
```

成功回應（HTTP 200）：
```json
{
    "http_status": 200,
    "status": "success"
}
```

> **注意**：Address 必須先從 Group 移除後才能刪除，否則 FortiGate 回傳錯誤。本程式嚴格遵循「先移除群組，再刪 Address」的順序。

#### 5.1.6 其他 API 操作

**查詢所有封鎖 IP（list_banned_ips）**

```bash
curl -sk \
  "https://${FGT_HOST}/api/v2/cmdb/firewall/addrgrp/ban_list" \
  -H "Authorization: Bearer ${FGT_TOKEN}" | python3 -m json.tool
```

程式解析 `results[0].member` 陣列，提取每個成員名稱（`ban_xxx_xxx_xxx_xxx`），再反向還原為 IP 字串。

**查詢特定 IP 資訊（get_ip_info）**

```bash
curl -sk \
  "https://${FGT_HOST}/api/v2/cmdb/firewall/address/ban_192_168_1_100" \
  -H "Authorization: Bearer ${FGT_TOKEN}" | python3 -m json.tool
```

回應：
```json
{
    "results": [
        {
            "name": "ban_192_168_1_100",
            "type": "ipmask",
            "subnet": "192.168.1.100 255.255.255.255",
            "comment": "Auto-banned: 3 failed VPN login attempts at 2026-02-13 10:32:00"
        }
    ]
}
```

封鎖時間與原因記錄在 `comment` 欄位中。

#### 5.1.7 錯誤碼與處理策略

| HTTP 狀態碼 | FortiGate 情境 | 程式處理方式 |
|------------|---------------|------------|
| 200 | 操作成功 | 正常繼續 |
| 404 | ban_list 群組不存在 | 自動 POST 建立空群組，再繼續 |
| 500 | Address 已存在（block 時）| 視為已封鎖，記錄日誌，繼續更新 Group |
| 500 | 並發 API 呼叫衝突 | Ban Queue 序列化解決，不會發生 |
| 401 | Token 無效或過期 | 記錄錯誤，停止執行 |
| 403 | IP 不在 trusthost | 記錄錯誤，停止執行 |

> **並發問題說明**：FortiGate API 不支援並發寫入，多個 IP 同時達到閾值時若並發呼叫 PUT addrgrp 會互相覆蓋。本系統使用 `asyncio.Queue` + 單一 Worker 確保所有 API 呼叫完全序列化。

#### 5.1.8 API 呼叫全流程圖

```
syslog_processor.py                fortigate_client.py          FortiGate
      │                                   │                         │
      │  _ban_worker() 取出 IP            │                         │
      │─────────────────────────────────>│                         │
      │                                   │  POST /firewall/address │
      │                                   │────────────────────────>│
      │                                   │  200 OK / 500 already   │
      │                                   │<────────────────────────│
      │                                   │  GET /firewall/addrgrp  │
      │                                   │────────────────────────>│
      │                                   │  200 OK {members:[...]} │
      │                                   │<────────────────────────│
      │                                   │  PUT /firewall/addrgrp  │
      │                                   │  (existing + new IP)    │
      │                                   │────────────────────────>│
      │                                   │  200 OK                 │
      │                                   │<────────────────────────│
      │  block_ip() returns True          │                         │
      │<─────────────────────────────────│                         │
      │                                   │                         │
      │  呼叫 notifier()                   │                         │
      │───> telegram_bot.send_ban_notification()                    │
```

---

### 5.2 Telegram Bot API

#### 5.2.1 API 基本資訊

| 項目 | 說明 |
|------|------|
| **Base URL** | `https://api.telegram.org/bot{TOKEN}` |
| **認證方式** | Bot Token（內嵌於 URL） |
| **框架** | python-telegram-bot 20.7（封裝官方 API） |
| **通訊方式** | Long Polling（主動向 Telegram Server 拉取 Updates） |
| **Bot Token 取得** | 透過 Telegram `@BotFather` 建立 Bot 後取得 |

#### 5.2.2 Long Polling 機制

Bot 不使用 Webhook，而是主動每隔一段時間向 Telegram Server 拉取新訊息（getUpdates）。python-telegram-bot 框架自動處理此循環：

```
Bot（本程式）                    Telegram Server
    │                                  │
    │  GET /getUpdates?timeout=30      │
    │  offset=last_update_id+1         │
    │─────────────────────────────────>│
    │                                  │ (等待最多 30 秒)
    │  [有新訊息] 回傳 Updates          │
    │<─────────────────────────────────│
    │  處理指令                         │
    │  POST /sendMessage               │
    │─────────────────────────────────>│
    │  200 OK                          │
    │<─────────────────────────────────│
    │  再次發送 getUpdates...           │
    │─────────────────────────────────>│
```

**curl 重現 getUpdates：**
```bash
BOT_TOKEN="<your_bot_token>"

curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getUpdates" | python3 -m json.tool
```

#### 5.2.3 主要 API 端點

| 端點 | 方法 | 功能 |
|------|------|------|
| `/getUpdates` | GET | 拉取新的 Update（使用者訊息） |
| `/sendMessage` | POST | 發送訊息到指定 Chat |
| `/getMe` | GET | 驗證 Token 並取得 Bot 資訊 |

#### 5.2.4 getUpdates — 接收使用者指令

**請求：**
```http
GET https://api.telegram.org/bot{TOKEN}/getUpdates?timeout=30&offset=123456790
```

參數說明：
- `timeout`：Long Polling 等待秒數（0 表示立即返回）
- `offset`：只取 update_id 大於此值的訊息（已處理的不再重複）

**回應（使用者發送了 `/unban 192.168.1.100`）：**
```json
{
    "ok": true,
    "result": [
        {
            "update_id": 123456790,
            "message": {
                "message_id": 201,
                "from": {
                    "id": 123456789,
                    "is_bot": false,
                    "first_name": "Admin",
                    "username": "admin_user"
                },
                "chat": {
                    "id": 123456789,
                    "type": "private"
                },
                "date": 1739411234,
                "text": "/unban 192.168.1.100",
                "entities": [
                    {
                        "offset": 0,
                        "length": 6,
                        "type": "bot_command"
                    }
                ]
            }
        }
    ]
}
```

python-telegram-bot 框架解析 `entities` 中 `type=bot_command` 的部分，提取指令名稱（`unban`）與參數（`192.168.1.100`），觸發對應的 `CommandHandler`。

#### 5.2.5 sendMessage — 發送通知與回應

**自動封鎖通知（由系統主動發送）：**

```http
POST https://api.telegram.org/bot{TOKEN}/sendMessage
Content-Type: application/json

{
    "chat_id": "123456789",
    "text": "[ALERT] IP 已自動封鎖\n\nIP 位址: 192.168.1.100\n失敗次數: 3 次 (10 分鐘內)\n封鎖時間: 2026-02-13 10:32:00\n來源系統: FortiGate\n事件類型: vpn_fail\n\n目前黑名單總數: 5\n\n使用 /list 查看完整黑名單\n使用 /unban 192.168.1.100 解除封鎖"
}
```

> **注意**：`parse_mode` 不設定（不使用 Markdown），避免 IP 位址中的 `.` 等字元被誤解析為格式符號，導致 Telegram API 回傳 400 Bad Request。

**curl 重現 sendMessage：**
```bash
BOT_TOKEN="<your_bot_token>"
CHAT_ID="<your_chat_id>"

curl -s -X POST \
  "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
  -H "Content-Type: application/json" \
  -d '{
    "chat_id": "'"${CHAT_ID}"'",
    "text": "[TEST] 手動測試通知\n\nIP 位址: 192.168.1.100\n封鎖時間: 2026-02-13 10:32:00"
  }' | python3 -m json.tool
```

成功回應（HTTP 200）：
```json
{
    "ok": true,
    "result": {
        "message_id": 202,
        "from": {"id": 7654321, "is_bot": true, "first_name": "SecurityBot"},
        "chat": {"id": 123456789, "type": "private"},
        "date": 1739411290,
        "text": "[TEST] 手動測試通知\n\nIP 位址: 192.168.1.100\n封鎖時間: 2026-02-13 10:32:00"
    }
}
```

失敗回應（Chat ID 錯誤，HTTP 400）：
```json
{
    "ok": false,
    "error_code": 400,
    "description": "Bad Request: chat not found"
}
```

**curl 重現 getMe（驗證 Token）：**
```bash
curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getMe" | python3 -m json.tool
```

回應：
```json
{
    "ok": true,
    "result": {
        "id": 7654321,
        "is_bot": true,
        "first_name": "FortiGate Security Bot",
        "username": "fortigate_security_bot",
        "can_join_groups": true,
        "can_read_all_group_messages": false,
        "supports_inline_queries": false
    }
}
```

#### 5.2.6 Telegram API 呼叫流程圖

```
使用者手機                 Telegram Server              本程式 (telegram_bot.py)
    │                           │                                │
    │  /unban 192.168.1.100     │                                │
    │──────────────────────────>│                                │
    │                           │  [Bot 正在 Long Polling]       │
    │                           │  GET /getUpdates 回傳 Update   │
    │                           │<───────────────────────────────│
    │                           │  200 OK {update_id: 790, ...} │
    │                           │───────────────────────────────>│
    │                           │                                │ 解析指令
    │                           │                                │ 驗證 user_id 是否在 admin_ids
    │                           │                                │ 驗證 IP 格式
    │                           │                                │ 呼叫 fortigate_client.unblock_ip()
    │                           │                                │ (FortiGate API 3 步驟)
    │                           │  POST /sendMessage             │
    │                           │<───────────────────────────────│
    │                           │  text: "已解除 192.168.1.100"  │
    │  收到回應訊息              │                                │
    │<──────────────────────────│                                │
```

#### 5.2.7 管理員驗證機制

```python
# telegram_bot.py
TELEGRAM_ADMIN_IDS = [int(id.strip()) for id in os.getenv("TELEGRAM_ADMIN_IDS", "").split(",")]

def is_admin(self, user_id: int) -> bool:
    return user_id in self.admin_ids
```

- 驗證依據：Telegram Update 中的 `message.from.id`（使用者數字 ID）
- 配置方式：`.env` 的 `TELEGRAM_ADMIN_IDS`（逗號分隔多個 ID）
- 取得自己的 User ID：傳訊息給 `@userinfobot` 或從 `/start` 回應查看

---

### 5.3 Syslog 協定（UDP 接收）

#### 5.3.1 Syslog 接收機制

本程式使用 Python `asyncio.DatagramProtocol` 建立 UDP Server，被動等待 FortiGate 推送 Syslog 封包：

```python
# syslog_processor.py
transport, protocol = await loop.create_datagram_endpoint(
    lambda: SyslogUDPProtocol(processor),
    local_addr=(host, port)  # 預設 0.0.0.0:5141
)
```

#### 5.3.2 FortiGate Syslog 格式

FortiGate 使用 RFC 3164 格式，本程式支援以下 3 種登入失敗訊息：

**格式 1 — VPN 登入失敗（提取 `remip` 或 `srcip`）**
```
<134>date=2026-02-13 time=10:32:00 devname="FG200F" devid="FG200F0000000001" logid="0101039424" type="event" subtype="vpn" level="information" vd="root" action="ssl-login-fail" tunneltype="ssl-web" tunnelid=0 remip=192.168.1.100 user="testuser" group="" dst_host="N/A" reason="sslvpn_login_unknown_user" msg="SSL VPN login fail"
```

**格式 2 — SSH / 管理介面登入失敗（提取 `srcip`）**
```
<133>date=2026-02-13 time=10:31:20 devname="FG200F" logid="0100032001" type="event" subtype="system" level="warning" vd="root" action="login" status="failed" srcip=192.168.1.100 user="admin" ui="ssh" reason="User credentials are wrong" msg="Admin login failed from srcip 192.168.1.100"
```

**格式 3 — 防火牆阻擋（提取 `src` 或 `srcip`）**
```
<134>date=2026-02-13 time=10:33:00 devname="FG200F" type="traffic" subtype="forward" action="deny" srcip=192.168.1.100 dstip=10.0.0.1 srcport=12345 dstport=443
```

#### 5.3.3 IP 提取正則表達式

```python
# syslog_processor.py — _parse_ip_from_syslog()
patterns = [
    r'remip=(\d+\.\d+\.\d+\.\d+)',   # VPN: remip=
    r'srcip=(\d+\.\d+\.\d+\.\d+)',   # SSH/防火牆: srcip=
    r'src=(\d+\.\d+\.\d+\.\d+)',     # 舊格式: src=
]
for pattern in patterns:
    match = re.search(pattern, message)
    if match:
        return match.group(1)
return None
```

**netcat 重現（模擬 FortiGate 發送 Syslog）：**
```bash
# 發送單筆 Syslog（Linux/Mac）
echo '<134>date=2026-02-13 time=10:32:00 subtype="vpn" action="ssl-login-fail" remip=192.168.1.100 user="test"' \
  | nc -u -w1 <監控伺服器IP> 5141

# Windows PowerShell
$udpClient = New-Object System.Net.Sockets.UdpClient
$bytes = [System.Text.Encoding]::UTF8.GetBytes('<134>date=2026-02-13 time=10:32:00 subtype="vpn" action="ssl-login-fail" remip=192.168.1.100')
$udpClient.Send($bytes, $bytes.Length, "<監控伺服器IP>", 5141)
$udpClient.Close()
```

連續發送 3 次（觸發自動封鎖閾值）：
```bash
for i in 1 2 3; do
    echo '<134>date=2026-02-13 time=10:32:00 subtype="vpn" action="ssl-login-fail" remip=192.168.1.100 user="test"' \
      | nc -u -w1 <監控伺服器IP> 5141
    sleep 1
done
```

---

## 6. 配置說明

### 6.1 環境變數 (.env)

所有設定透過 `scripts/.env` 檔案配置：

```bash
# FortiGate API 設定
FORTIGATE_HOST=<your-fortigate-ip>   # FortiGate IP 或域名
FORTIGATE_TOKEN=<your-api-token>     # API Token
FORTIGATE_VERIFY_SSL=false           # 是否驗證 SSL 憑證

# Telegram Bot 設定
TELEGRAM_BOT_TOKEN=<your-bot-token>  # Bot Token (從 @BotFather 取得)
TELEGRAM_ADMIN_IDS=        # 管理員 User ID（逗號分隔）
TELEGRAM_CHAT_ID=          # 通知目標 Chat ID

# 系統設定
USE_REAL_FORTIGATE=false             # true=真實API, false=Mock測試
SYSLOG_HOST=0.0.0.0                  # Syslog 監聽位址
SYSLOG_PORT=5141                     # Syslog 監聽端口
FAIL_THRESHOLD=3                     # 失敗次數閾值
TIME_WINDOW=600                      # 時間窗口（秒）
WHITELIST=10.0.0.0/8,192.168.0.1     # 白名單（逗號分隔）

# 日誌設定
LOG_LEVEL=INFO
LOG_FILE=logs/security_bot.log
```

### 6.2 FortiGate 端設定

#### 6.2.1 Syslog Server 設定

```bash
config log syslogd setting
    set status enable
    set server "容器IP"           # 容器的 IP 位址
    set port 5141                 # Syslog 端口
    set mode udp                  # UDP 協定
    set format default
end

config log syslogd filter
    set severity information      # 記錄等級
end
```

#### 6.2.2 Firewall Policy 設定

建立封鎖 Policy（必須手動建立）：

```bash
config firewall policy
    edit 10
        set name "Auto-Ban-Policy"
        set srcintf "wan1"
        set dstintf "any"
        set srcaddr "ban_list"              # 來源是 ban_list Group
        set dstaddr "all"
        set action deny                     # 拒絕流量
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

**重要**：Policy 必須放在允許流量的 Policy 之前。

#### 6.2.3 Local-in Policy 設定

封鎖 ban_list 的 IP 直接連接到 FortiGate 本身（VPN 驗證層），避免已封鎖的 IP 持續觸發登入失敗事件並產生 Syslog：

```bash
config firewall local-in-policy
    edit 1
        set intf "port1"          # WAN 介面
        set srcaddr "ban_list"
        set dstaddr "all"
        set action deny
        set service "ALL"
        set schedule "always"
    next
end
```

**Local-in Policy 與 Firewall Policy 的差異**：

| | Firewall Policy | Local-in Policy |
|--|----------------|-----------------|
| **攔截對象** | 穿越 FortiGate 的流量 | 目的地為 FortiGate 本身的流量 |
| **效果** | 阻止攻擊者進入內網 | 阻止攻擊者觸發 VPN 驗證 |
| **封鎖 Syslog** | 否（VPN 驗證在 Policy 之前） | 是（在驗證層直接拒絕） |

---

## 7. 程式碼結構

### 7.1 目錄結構

```
security_TG_BOT/
├── scripts/
│   ├── .env                          # 環境變數（不提交 Git）
│   ├── .env.example                  # 環境變數範本
│   └── security_TG_BOT/
│       ├── .venv/                    # Python 虛擬環境
│       ├── main.py                   # 主程式入口
│       ├── fortigate_client.py       # FortiGate API Client
│       ├── syslog_processor.py       # Syslog 處理器
│       ├── telegram_bot.py           # Telegram Bot
│       ├── test_syslog_sender.py     # Syslog 測試工具
│       ├── test_telegram_notification.py  # Telegram 測試
│       └── requirements.txt          # Python 依賴
├── docs/
│   ├── ARCHITECTURE.md               # 本文件
├── logs/                             # 日誌目錄（Docker volume）
├── Dockerfile                        # Docker 映像檔定義
├── docker-compose.yml                # Docker Compose 配置
├── .dockerignore                     # Docker 忽略檔案
├── .gitignore                        # Git 忽略檔案
├── requirements.txt                  # Python 依賴（根目錄）
```

### 7.2 主要程式檔案說明

| 檔案 | 行數 | 職責 | 關鍵類別/函數 |
|------|------|------|--------------|
| `main.py` | ~250 | 系統整合與生命週期管理 | `AutoBanSystem` |
| `fortigate_client.py` | ~360 | FortiGate API 操作 | `FortiGateClient` |
| `syslog_processor.py` | ~200 | Syslog 接收與處理 | `SyslogProcessor`, `SyslogUDPProtocol` |
| `telegram_bot.py` | ~400 | Telegram Bot 與通知 | `SecurityBot`, `MockFortiGateClient` |

### 7.3 程式碼依賴關係

```
main.py
 ├─ import fortigate_client (FortiGateClient)
 ├─ import syslog_processor (SyslogProcessor)
 └─ import telegram_bot (SecurityBot, MockFortiGateClient)

fortigate_client.py
 ├─ import httpx (HTTP Client)
 └─ import dotenv (環境變數)

syslog_processor.py
 ├─ import asyncio (UDP Server)
 └─ import re (正則表達式解析)

telegram_bot.py
 ├─ import telegram (Telegram API)
 ├─ import telegram.ext (Bot 框架)
 └─ import fortigate_client (API 操作)
```

### 7.4 執行入口

**本機執行**：
```bash
cd scripts/security_TG_BOT
.venv/Scripts/python main.py
```

**執行流程**：
```
1. main.py:242 - if __name__ == "__main__"
2. main.py:243 - asyncio.run(main())
3. main.py:237 - system = AutoBanSystem()
4. main.py:238 - await system.start()
5. AutoBanSystem.start() - 初始化三大模組
6. 進入事件循環，等待 Syslog/Telegram Updates
```

---

### 8. 技術參考

- [FortiGate REST API 文件](https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/)
- [python-telegram-bot 文件](https://docs.python-telegram-bot.org/)
- [AsyncIO 官方文件](https://docs.python.org/3/library/asyncio.html)


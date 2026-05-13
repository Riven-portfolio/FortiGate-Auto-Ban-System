# FortiGate Auto-Ban System 軟體設計文件

**版本**: 1.1
**文件建立日期**: 2026-02-03
**最後更新**: 2026-02-13
**專案狀態**: 整合完成，可運行測試

---

## 📋 目錄

1. [專案概述](#1-專案概述)
2. [系統架構](#2-系統架構)
3. [技術棧](#3-技術棧)
4. [核心功能模組](#4-核心功能模組)
5. [資料流程設計](#5-資料流程設計)
6. [API 與介面設計](#6-api-與介面設計)
7. [安全性設計](#7-安全性設計)
8. [性能優化策略](#8-性能優化策略)
9. [錯誤處理機制](#9-錯誤處理機制)
10. [部署架構](#10-部署架構)
11. [測試策略](#11-測試策略)
12. [未來發展規劃](#12-未來發展規劃)

---

## 1. 專案概述

### 1.1 專案簡介

**FortiGate Auto-Ban System** 是一個自動化安全防禦系統，透過整合 FortiGate 防火牆 REST API 與 Telegram Bot，實現即時威脅偵測與自動封鎖功能。系統監控登入失敗事件，當單一 IP 在時間窗口內達到失敗閾值時，自動將其加入 FortiGate 黑名單並透過 Telegram 發送通知。

### 1.2 核心目標

- **即時性**: 在威脅發生後 10 秒內完成自動封鎖
- **準確性**: 精準識別暴力破解攻擊，避免誤封正常使用者
- **可靠性**: 7x24 小時穩定運行，故障自動恢復
- **可擴展性**: 支援多台 FortiGate 設備與多種日誌來源
- **易用性**: Telegram Bot 介面直覺，支援指令查詢與管理

### 1.3 主要特性

#### 基礎功能
✅ **Syslog 協定整合**: 接收並解析 FortiGate Syslog 格式日誌
✅ **多種日誌來源支援**: FortiGate VPN、SSH、自訂應用程式
✅ **時間窗口計數**: 10 分鐘內連續失敗 3 次觸發封鎖
✅ **FortiGate API 整合**: 自動新增 IP 到 Address Ban List
✅ **Telegram 即時通知**: 封鎖確認與黑名單列表推送

#### 進階功能
✅ **白名單機制**: 避免誤封內部 IP 與管理 IP
✅ **自動解封**: 可設定 24 小時後自動移除黑名單
✅ **Redis 分散式儲存**: 支援多實例部署
✅ **Prometheus Metrics**: 效能監控與告警
✅ **Web Dashboard**: 即時查看系統狀態與統計資料

### 1.4 使用場景

- 🔒 企業 VPN 暴力破解防護
- 🖥️ Linux SSH 登入失敗自動封鎖
- 🌐 Web 應用程式登入保護
- 🏢 多分點統一安全防護
- 📊 資安事件監控與分析

---

## 2. 系統架構

### 2.1 整體架構圖

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FortiGate 防火牆                              │
│  • VPN 登入失敗事件                                                   │
│  • SSH 登入失敗事件                                                   │
│  • Syslog 發送到監控系統                                              │
└────────────────────────┬────────────────────────────────────────────┘
                         │ Syslog (UDP 514 / TCP 514)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Python Syslog Server                             │
│  • 接收 Syslog 訊息                                                   │
│  • 解析日誌（正規表達式）                                              │
│  • 提取 IP、事件類型、時間戳記                                         │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 內部事件
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Event Processor                                  │
│  • 事件驗證與過濾                                                     │
│  • 白名單檢查                                                         │
│  • 計數器管理（Redis）                                                │
│  • 時間窗口控制（10 分鐘）                                             │
└────────────────────────┬────────────────────────────────────────────┘
                         │ 達到閾值（3 次）
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Action Handler                                   │
│  • 呼叫 FortiGate API 封鎖 IP                                         │
│  • 記錄封鎖事件到資料庫                                                │
│  • 觸發 Telegram 通知                                                 │
└────────────────────────┬────────────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
┌──────────────────┐          ┌──────────────────────┐
│ FortiGate API    │          │  Telegram Bot        │
│ • 新增 Address   │          │  • 發送封鎖通知       │
│ • 查詢黑名單     │          │  • 列出所有黑名單     │
│ • 刪除 Address   │          │  • 指令查詢統計       │
└──────────────────┘          └──────────────────────┘
```

### 2.2 核心元件說明

#### 2.2.1 Syslog Server
- **角色**: 接收並解析日誌訊息
- **功能**:
  - UDP/TCP Syslog 協定支援
  - 多種日誌格式解析（FortiGate、Linux authlog）
  - 非阻塞式事件處理（asyncio）
  - 日誌持久化（選配）

#### 2.2.2 Event Processor
- **角色**: 事件處理與計數管理
- **功能**:
  - IP 失敗次數計數（Redis）
  - 時間窗口管理（TTL）
  - 白名單過濾
  - 閾值判斷邏輯

#### 2.2.3 Action Handler
- **角色**: 執行封鎖動作
- **功能**:
  - FortiGate API 呼叫
  - Retry 機制（3 次重試）
  - Telegram 通知發送
  - 事件記錄到資料庫

#### 2.2.4 FortiGate API Client
- **角色**: FortiGate REST API 封裝
- **功能**:
  - API Token 認證
  - Address 物件管理（CRUD）
  - Policy 規則綁定
  - Connection Pool 管理

#### 2.2.5 Telegram Bot
- **角色**: 使用者介面與通知
- **功能**:
  - 接收封鎖通知
  - 指令查詢（`/list`, `/stats`, `/unban`）
  - 管理員權限控制
  - 訊息格式化

#### 2.2.6 Redis Cache
- **角色**: 分散式計數與快取
- **功能**:
  - IP 失敗計數（INCR + EXPIRE）
  - 黑名單快取（SET）
  - 分散式鎖（避免重複封鎖）

#### 2.2.7 整合層（Integration Layer）✨ NEW
- **角色**: 統一系統入口與模組協調
- **實作**: `main.py` - `AutoBanSystem` 類別
- **功能**:
  - 初始化並協調三大模組（FortiGate Client、Syslog Processor、Telegram Bot）
  - 環境變數控制 Mock/Real API 切換
  - 非阻塞式並發執行（asyncio）
  - 依賴注入（Syslog Processor 注入 FortiGate Client 和通知函數）
  - 整合通知流程（Syslog → 自動封鎖 → Telegram）
  - 優雅關閉機制（Graceful Shutdown）
  - Windows/Linux 信號處理相容性

---

## 3. 技術棧

### 3.1 程式語言與框架

| 元件 | 技術 | 版本 | 用途 |
|------|------|------|------|
| **核心程式** | Python | 3.11+ | 主要開發語言 |
| **非同步處理** | asyncio | 標準庫 | 非阻塞 I/O |
| **Telegram Bot** | python-telegram-bot | 20.7+ | Bot 框架 |
| **HTTP Client** | httpx | 0.25+ | FortiGate API 呼叫 |
| **Syslog 解析** | syslog-rfc5424-parser | 0.2+ | RFC 5424 解析 |

### 3.2 儲存與快取

| 技術 | 用途 | 部署方式 |
|------|------|----------|
| **Redis** | IP 計數、分散式鎖、快取 | Docker / Standalone |
| **SQLite** | 封鎖事件記錄（開發環境） | 內嵌檔案 |
| **PostgreSQL** | 封鎖事件記錄（生產環境） | Docker / Managed Service |

### 3.3 基礎設施

| 元件 | 技術 | 用途 |
|------|------|------|
| **FortiGate VM** | FortiOS 7.0+ | 測試環境防火牆 |
| **Docker** | 24.0+ | 容器化部署 |
| **Docker Compose** | 2.20+ | 多容器編排 |
| **Prometheus** | 2.45+ | 效能監控（選配） |
| **Grafana** | 10.0+ | 監控視覺化（選配） |

### 3.4 開發工具

- **版本控制**: Git
- **套件管理**: Poetry / pip
- **程式碼品質**: Ruff (Linter + Formatter)
- **型別檢查**: mypy
- **測試框架**: pytest, pytest-asyncio
- **CI/CD**: GitHub Actions（選配）

---

## 4. 核心功能模組

### 4.1 Syslog 接收模組

#### 4.1.1 功能描述
接收來自 FortiGate 或其他系統的 Syslog 訊息，支援 UDP 和 TCP 協定。

#### 4.1.2 關鍵類別
```python
class SyslogServer:
    async def start(self, host: str, port: int, protocol: str)
    async def handle_message(self, message: bytes, addr: tuple)

class SyslogParser:
    def parse(self, raw_message: str) -> LogEvent
    def extract_ip(self, message: str) -> Optional[str]
    def extract_event_type(self, message: str) -> str
```

#### 4.1.3 支援的日誌格式
- FortiGate Syslog (RFC 3164 / RFC 5424)
- Linux auth.log
- 自訂 JSON 格式

### 4.2 事件處理模組

#### 4.2.1 功能描述
計數 IP 失敗次數，判斷是否達到封鎖閾值。

#### 4.2.2 關鍵類別
```python
class EventProcessor:
    def __init__(self, redis_client: Redis, config: Config)
    async def process_event(self, event: LogEvent) -> ProcessResult
    async def increment_counter(self, ip: str) -> int
    async def check_threshold(self, ip: str, count: int) -> bool
    def is_whitelisted(self, ip: str) -> bool
```

#### 4.2.3 計數機制
- 使用 Redis INCR 原子操作
- 設定 TTL（600 秒 = 10 分鐘）
- 達到閾值後重置計數器

### 4.3 FortiGate API 模組

#### 4.3.1 功能描述
封裝 FortiGate REST API，提供 IP 封鎖與查詢功能。

#### 4.3.2 關鍵類別
```python
class FortiGateClient:
    def __init__(self, host: str, api_token: str, verify_ssl: bool)
    async def block_ip(self, ip: str, comment: str) -> bool
    async def unblock_ip(self, ip: str) -> bool
    async def list_banned_ips(self) -> List[str]
    async def get_ban_list_policy(self) -> Optional[Policy]
```

#### 4.3.3 API 端點
- `POST /api/v2/cmdb/firewall/address` - 新增 Address 物件
- `DELETE /api/v2/cmdb/firewall/address/{name}` - 刪除 Address
- `GET /api/v2/cmdb/firewall/address` - 查詢所有 Address
- `GET /api/v2/cmdb/firewall/policy` - 查詢 Policy 規則

### 4.4 Telegram Bot 模組

#### 4.4.1 功能描述
提供 Telegram 介面，發送通知與接收指令。

#### 4.4.2 支援的指令
```
/start          - 啟動 Bot 並顯示說明
/list           - 列出所有黑名單 IP
/stats          - 顯示統計資料（今日封鎖數、總封鎖數）
/unban <IP>     - 手動解除封鎖（管理員）
/whitelist <IP> - 加入白名單（管理員）
/status         - 顯示系統狀態
```

#### 4.4.3 通知格式
```
🚫 IP 已自動封鎖

IP 位址: 192.168.1.100
失敗次數: 3 次（10 分鐘內）
封鎖時間: 2026-02-03 14:30:25
來源: FortiGate VPN

目前黑名單 (5):
• 192.168.1.100
• 10.0.0.50
• 203.0.113.45
• 198.51.100.78
• 172.16.0.99
```

### 4.5 資料持久化模組

#### 4.5.1 功能描述
記錄封鎖事件到資料庫，供查詢與分析。

#### 4.5.2 資料模型
```python
class BanEvent:
    id: int
    ip_address: str
    ban_time: datetime
    unban_time: Optional[datetime]
    reason: str
    fail_count: int
    source: str  # 'vpn', 'ssh', 'web'
    is_active: bool
```

---

## 5. 資料流程設計

### 5.1 系統啟動流程 ✨ NEW

```
1. 執行 main.py
   ↓
2. AutoBanSystem 初始化
   ├─ 載入環境變數 (.env)
   ├─ 根據 USE_REAL_FORTIGATE 選擇 FortiGate Client（Mock/Real）
   ├─ 初始化 Telegram Bot（註冊指令處理器）
   └─ 初始化 Syslog Processor（注入 FortiGate Client 和通知函數）
   ↓
3. 啟動所有元件（非阻塞並發）
   ├─ Syslog UDP Server (port 5141)
   ├─ Telegram Bot 輪詢 (updater.start_polling)
   └─ 註冊信號處理器 (SIGINT/SIGTERM)
   ↓
4. 進入主循環（asyncio.sleep(1)）
   等待事件或 Ctrl+C
```

### 5.2 登入失敗事件流程（整合版）✨ UPDATED

```
1. FortiGate 偵測到 VPN 登入失敗
   ↓
2. FortiGate 發送 Syslog 到監控系統（UDP 5141）
   ↓
3. Syslog Processor 接收訊息
   ├─ DatagramProtocol.datagram_received()
   └─ 解析並提取 IP（192.168.1.100）
   ↓
4. 檢查白名單（通過）
   ↓
5. 記憶體 dict 累計失敗次數
   fail_counter["192.168.1.100"] = 3
   ↓
6. 達到閾值，觸發自動封鎖
   ↓
7. 清空計數器 → 加入封鎖佇列（ban_queue）
   ↓
8. Ban Worker 依序從佇列取出，呼叫 FortiGate Client.block_ip("192.168.1.100", ...)
   ├─ 建立 Address: ban_192_168_1_100
   └─ 加入 Group: ban_list
   ↓
9. 呼叫 notifier 函數（依賴注入）
   ├─ main.telegram_notification(ip="192.168.1.100", fail_count=3, ...)
   └─ telegram_bot.send_ban_notification(...)
   ↓
10. Telegram Bot 發送通知到指定 Chat ID
   [ALERT] IP 已封鎖
   IP: 192.168.1.100
   失敗次數: 3
   來源系統: FortiGate
```

### 5.3 優雅關閉流程 ✨ NEW

```
1. 使用者按 Ctrl+C（觸發 SIGINT）
   ↓
2. 信號處理器呼叫 AutoBanSystem.shutdown()
   ↓
3. 停止 Telegram Bot
   ├─ app.updater.stop()
   ├─ app.stop()
   └─ app.shutdown()
   ↓
4. 停止 Syslog Processor
   └─ syslog_processor.stop_server()
   ↓
5. 關閉 FortiGate Client
   └─ fortigate_client.close()（關閉 HTTP 連線）
   ↓
6. 系統完全關閉，釋放所有資源
```

### 5.4 Redis 資料結構

```
# IP 失敗計數
Key: "fail:{ip}"
Type: String (整數)
TTL: 600 秒
Value: "3"

# 分散式鎖（避免重複封鎖）
Key: "lock:ban:{ip}"
Type: String
TTL: 10 秒
Value: "1"

# 黑名單快取
Key: "blacklist"
Type: Set
Value: {"192.168.1.100", "10.0.0.50", ...}
```

### 5.5 FortiGate Address 物件格式

```json
{
  "name": "ban_192.168.1.100",
  "type": "ipmask",
  "subnet": "192.168.1.100/32",
  "comment": "Auto-banned by TG Bot at 2026-02-03 14:30:25"
}
```

---

## 6. API 與介面設計

### 6.1 FortiGate REST API

#### 6.1.1 認證方式
```http
GET /api/v2/cmdb/firewall/address
Authorization: Bearer YOUR_API_TOKEN
```

#### 6.1.2 新增封鎖 IP
```http
POST /api/v2/cmdb/firewall/address
Content-Type: application/json

{
  "name": "ban_192.168.1.100",
  "type": "ipmask",
  "subnet": "192.168.1.100/32",
  "comment": "Auto-banned at 2026-02-03 14:30:25"
}
```

**Response**:
```json
{
  "http_status": 200,
  "results": {
    "status": "success",
    "http_status": 200
  }
}
```

#### 6.1.3 查詢所有黑名單
```http
GET /api/v2/cmdb/firewall/address?filter=name=@ban_
```

#### 6.1.4 刪除封鎖 IP
```http
DELETE /api/v2/cmdb/firewall/address/ban_192.168.1.100
```

### 6.2 內部事件介面

#### 6.2.1 LogEvent 資料結構
```python
@dataclass
class LogEvent:
    timestamp: datetime
    source_ip: str
    event_type: str  # 'vpn_fail', 'ssh_fail', 'web_fail'
    username: Optional[str]
    source_system: str  # 'fortigate', 'linux', 'custom'
    raw_message: str
```

#### 6.2.2 ProcessResult 資料結構
```python
@dataclass
class ProcessResult:
    action_taken: bool  # True if IP was banned
    current_count: int
    threshold_reached: bool
    ip_address: str
    message: str
```

---

## 7. 安全性設計

### 7.1 API Token 保護

- **儲存方式**: 環境變數或加密設定檔
- **權限最小化**: FortiGate API Token 只給予必要權限
- **定期輪換**: 建議每 90 天更換 API Token

### 7.2 Telegram Bot 權限控制

```python
ADMIN_USER_IDS = [123456789, 987654321]  # 管理員白名單

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_USER_IDS
```

- 危險指令（`/unban`, `/whitelist`）需管理員權限
- Bot Token 保護（環境變數）

### 7.3 白名單機制

```python
WHITELIST = [
    "10.0.0.0/8",      # 內部網路
    "192.168.0.1",     # 管理 IP
    "203.0.113.1",     # 特定夥伴 IP
]
```

- 防止誤封內部 IP
- 支援 CIDR 格式

### 7.4 防止濫用

- **Rate Limiting**: 限制 Telegram 指令執行頻率
- **分散式鎖**: 避免同一 IP 重複封鎖
- **日誌審計**: 記錄所有封鎖與解封操作

---

## 8. 性能優化策略

### 8.1 封鎖佇列機制（Ban Queue）

**問題背景**：多個 IP 同時達到閾值時，並發的 `block_ip()` API 呼叫導致 FortiGate 返回 HTTP 500。

**設計**：採用 `asyncio.Queue` + 單一 Worker 模式，確保 FortiGate API 呼叫完全序列化：

```python
# SyslogProcessor.__init__()
self.ban_queue = asyncio.Queue()
self.banning_ips = set()  # 防止同一 IP 重複加入佇列
self._worker_task = None

# _auto_ban()：加入佇列（立刻清空計數器，防止重複觸發）
if ip in self.banning_ips:
    return
del self.failure_counter[ip]
self.banning_ips.add(ip)
await self.ban_queue.put((ip, count))

# _ban_worker()：依序處理，同時最多只有 1 個 API 呼叫
async def _ban_worker(self):
    while True:
        ip, count = await self.ban_queue.get()
        try:
            await self.fortigate.block_ip(ip, comment)
        finally:
            self.banning_ips.discard(ip)
            self.ban_queue.task_done()
```

**特性**：
- Worker 在 `start_server()` 啟動，`stop_server()` 時取消
- `banning_ips` set 防止同一 IP 重複加入佇列
- `finally` 確保無論成功失敗都從集合移除，允許後續重新觸發

### 8.2 非同步處理

- 使用 `asyncio` 非阻塞 I/O
- Syslog 接收與處理分離（Queue）
- 並行處理多個事件

### 8.3 連線池管理

```python
# HTTP 連線池
http_client = httpx.AsyncClient(
    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    timeout=httpx.Timeout(10.0)
)
```

### 8.3 Redis 效能優化

- Pipeline 批次操作
- 連線池複用
- 合理設定 TTL

### 8.4 快取策略

- 黑名單快取（避免重複查詢 FortiGate）
- 白名單快取（記憶體載入）

### 8.5 效能指標

| 指標 | 目標值 |
|------|--------|
| Syslog 處理延遲 | < 100ms |
| FortiGate API 回應時間 | < 500ms |
| 事件端到端處理時間 | < 2 秒 |
| 系統記憶體使用 | < 500MB |
| 支援並發事件數 | 100+ events/sec |

---

## 9. 錯誤處理機制

### 9.1 Syslog Server 錯誤處理

```python
try:
    event = parser.parse(message)
except ParseError as e:
    logger.warning(f"Failed to parse message: {e}")
    metrics.syslog_parse_errors.inc()
    return
```

### 9.2 FortiGate API 錯誤處理

```python
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
async def block_ip_with_retry(ip: str):
    try:
        result = await fortigate.block_ip(ip)
        return result
    except httpx.TimeoutException:
        logger.error(f"FortiGate API timeout for {ip}")
        raise
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            logger.error(f"IP {ip} already exists in ban list")
            return False
        raise
```

### 9.3 Redis 連線失敗處理

- 自動重連機制
- Fallback 到記憶體計數（Degraded Mode）
- 告警通知管理員

### 9.4 Telegram Bot 錯誤處理

- 訊息發送失敗重試（3 次）
- Rate Limit 錯誤處理（延遲重送）
- 網路錯誤降級（記錄到日誌）

---

## 10. 部署架構

### 10.1 單機部署（開發/測試）

```
┌─────────────────────────────────────────┐
│         單一 Linux 伺服器                │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Docker Compose                 │   │
│  │                                 │   │
│  │  ├─ security-bot (Python)      │   │
│  │  ├─ redis                       │   │
│  │  └─ postgresql (optional)      │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  FortiGate VM                   │   │
│  │  (VirtualBox / VMware)          │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

### 10.2 生產環境部署

```
┌──────────────────┐
│  FortiGate       │
│  (Hardware)      │
└────────┬─────────┘
         │ Syslog
         ▼
┌──────────────────────────────┐
│  Kubernetes Cluster          │
│                              │
│  ┌────────────────────────┐  │
│  │  security-bot          │  │
│  │  (Deployment x2)       │  │
│  └────────────────────────┘  │
│                              │
│  ┌────────────────────────┐  │
│  │  Redis Sentinel        │  │
│  │  (StatefulSet x3)      │  │
│  └────────────────────────┘  │
│                              │
│  ┌────────────────────────┐  │
│  │  PostgreSQL            │  │
│  │  (StatefulSet)         │  │
│  └────────────────────────┘  │
└──────────────────────────────┘
```

### 10.3 Docker Compose 設定

#### 當前實作（MVP 版本）

簡化版部署，使用記憶體儲存，適合單機環境。

```yaml
version: '3.8'

services:
  autoban-system:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: fortigate-autoban
    restart: unless-stopped

    environment:
      - PYTHONUNBUFFERED=1
      # 注意：不要在此設定 USE_REAL_FORTIGATE，否則會覆蓋 env_file 的值
      # 請直接在 scripts/.env 中設定 USE_REAL_FORTIGATE=true/false

    env_file:
      - scripts/.env

    ports:
      - "5141:5141/udp"  # Syslog 接收端口

    volumes:
      - ./logs:/app/logs
      - ./scripts/.env:/app/.env:ro

    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M

    healthcheck:
      test: ["CMD-SHELL", "python -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"\", 0)); s.close()' || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s

    networks:
      - autoban-network

networks:
  autoban-network:
    driver: bridge
```

**關鍵設計決策：**
- **Port 5141**: 避免 Windows 環境權限問題（Port 514 需要 root）
- **記憶體儲存**: 使用 Python dict 計數器，不依賴 Redis（簡化部署）
- **資源限制**: 限制 CPU 1.0、記憶體 512M（防止資源耗盡）
- **健康檢查**: 每 30 秒檢查 UDP socket 可用性
- **日誌持久化**: Volume 掛載確保日誌不丟失

#### 未來擴展（生產環境）

進階部署配置，支援高可用性與多實例。

```yaml
version: '3.8'

services:
  autoban-system:
    build: .
    environment:
      - REDIS_HOST=redis
      - FORTIGATE_HOST=${FORTIGATE_HOST}
      - FORTIGATE_TOKEN=${FORTIGATE_TOKEN}
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
    ports:
      - "5141:5141/udp"
    depends_on:
      - redis
    restart: unless-stopped
    deploy:
      replicas: 2  # 多實例部署

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  postgresql:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=autoban
      - POSTGRES_USER=autoban
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  redis_data:
  postgres_data:
```

**詳細部署指南請參考**: [DEPLOYMENT.md](./docs/DEPLOYMENT.md)

---

## 11. 測試策略

### 11.1 單元測試

```python
# 測試事件處理
async def test_event_processor_threshold():
    processor = EventProcessor(mock_redis, config)

    # 模擬 3 次失敗
    for _ in range(3):
        result = await processor.process_event(
            LogEvent(ip="192.168.1.100", event_type="vpn_fail")
        )

    assert result.threshold_reached is True

# 測試 FortiGate API
async def test_block_ip_success():
    client = FortiGateClient(host, token)
    result = await client.block_ip("192.168.1.100")
    assert result is True
```

### 11.2 整合測試

- Syslog Server 接收測試
- Redis 計數正確性測試
- FortiGate API 完整流程測試
- Telegram Bot 通知測試

### 11.3 壓力測試

- 模擬每秒 100 個 Syslog 訊息
- 驗證系統穩定性與效能
- 測試 FortiGate API Rate Limit 處理

### 11.4 測試覆蓋率目標

- 核心邏輯：> 90%
- API 呼叫：> 80%
- 整體專案：> 70%

---

## 12. 未來發展規劃

### 12.1 Phase 2 功能（基礎擴充）

#### 12.1.1 Web Dashboard（Flask/FastAPI）
- 即時顯示系統狀態
- 黑名單管理介面
- 統計圖表視覺化
- 手動封鎖/解封操作

#### 12.1.2 多台 FortiGate 支援
- 支援多個 FortiGate 實例
- 統一管理多個防火牆
- 分散式封鎖策略
- 負載平衡考量

#### 12.1.3 自動解封機制（24 小時後）
- 定時檢查封鎖時間
- 自動移除過期封鎖
- 可設定不同的解封策略
- 永久封鎖清單管理

#### 12.1.4 GeoIP 查詢與顯示
- 顯示 IP 所屬國家/城市
- 統計攻擊來源地區
- 地圖視覺化
- 國家層級封鎖策略

#### 12.1.5 封鎖原因分析報告
- 每日/每週/每月統計報告
- 攻擊趨勢分析
- 最活躍攻擊 IP 排行
- PDF 報告匯出

---

### 12.2 Phase 3 功能（進階整合）

#### 12.2.1 FortiGate 日誌 API 整合（需要 Log & Report 權限）

**功能描述**：
透過 FortiGate REST API 直接查詢日誌，作為 Syslog 的補充或替代方案。

**使用場景**：

1. **歷史日誌查詢**
   ```python
   # Telegram 指令：/history <IP>
   # 查詢特定 IP 的歷史攻擊記錄

   GET /api/v2/monitor/log/device
   params: {
       "filter": f"srcip=={ip}",
       "start": 1707000000,  # 過去 24 小時
       "rows": 100
   }
   ```

   **需要權限**：`Log & Report: Read`

   **優點**：
   - 可查詢過去的日誌（Syslog 只有即時）
   - 補充遺失的 Syslog 訊息
   - 支援複雜過濾條件

2. **統計報表自動生成**
   ```python
   # 每日自動產生統計報表
   # 包含：封鎖次數、來源分布、時間趨勢

   GET /api/v2/monitor/log/device
   params: {
       "logtype": "event",
       "subtype": "vpn",
       "filter": "action==deny"
   }
   ```

   **需要權限**：`Log & Report: Read`

   **優點**：
   - 不依賴外部資料庫
   - FortiGate 原生日誌完整
   - 可產生正式報表

3. **被封鎖 IP 的連線嘗試監控**
   ```python
   # 監控被封鎖後仍在嘗試連線的 IP
   # 判斷攻擊者的持續性

   GET /api/v2/monitor/firewall/session
   params: {
       "filter": f"srcaddr=={blocked_ip}"
   }
   ```

   **需要權限**：`Log & Report: Read`

   **優點**：
   - 評估攻擊威脅程度
   - 決定是否需要永久封鎖
   - 提供更多資安情報

4. **攻擊模式分析**
   ```python
   # 分析攻擊時間、頻率、目標
   # 識別 DDoS、暴力破解等攻擊模式

   GET /api/v2/monitor/log/ips-archive
   ```

   **需要權限**：`Log & Report: Read`

   **優點**：
   - 深度威脅分析
   - 預測性防禦
   - 安全態勢評估

**API 權限需求變更**：
```yaml
目前（Phase 1）:
  Firewall: Read/Write

Phase 3 加入後:
  Firewall: Read/Write
  Log & Report: Read  ← 新增
```

**實作考量**：
- API 呼叫頻率限制（避免過度查詢）
- 日誌資料量大時的效能優化
- 與 Syslog 的互補策略（不是替代）

---

#### 12.2.2 使用者行為分析（需要 User & Device 權限）

**功能描述**：
分析使用者登入行為，識別異常模式。

**使用場景**：

1. **識別被盜用的合法帳號**
   ```python
   # 分析使用者的登入模式
   # 偵測異常登入（如：凌晨登入、異地登入）

   GET /api/v2/cmdb/user/local
   GET /api/v2/monitor/user/device
   ```

   **需要權限**：`User & Device: Read`

   **優點**：
   - 區分「暴力破解」vs「帳號被盜」
   - 更精準的威脅判斷
   - 降低誤封合法使用者

2. **裝置白名單管理**
   ```python
   # 允許特定裝置不受封鎖影響
   # 基於 MAC 位址或裝置 ID

   GET /api/v2/cmdb/user/device
   POST /api/v2/cmdb/user/device
   ```

   **需要權限**：`User & Device: Read/Write`

**API 權限需求變更**：
```yaml
Phase 3 進階功能:
  Firewall: Read/Write
  Log & Report: Read
  User & Device: Read  ← 新增（選配）
```

---

#### 12.2.3 機器學習異常偵測
- 訓練模型識別攻擊模式
- 自動調整封鎖閾值
- 預測性防禦機制
- 減少誤報與漏報

#### 12.2.4 支援其他防火牆品牌
- Palo Alto Networks REST API
- Cisco ASA REST API
- pfSense API
- 統一介面設計模式

#### 12.2.5 SIEM 系統整合
- Splunk 整合
- ELK Stack 整合
- QRadar 整合
- 日誌標準化處理

#### 12.2.6 自動化回應腳本（SOAR）
- Playbook 設計
- 自動化工作流程
- 事件關聯分析
- 回應動作編排

#### 12.2.7 移動 App 推送通知
- iOS/Android App
- 推送通知整合
- 即時告警
- 遠端管理功能

---

### 12.3 API 權限演進路徑

| Phase | Firewall | Log & Report | User & Device | 說明 |
|-------|----------|--------------|---------------|------|
| **Phase 1（當前）** | Read/Write | None | None | 基本封鎖功能 |
| **Phase 2** | Read/Write | None | None | 擴充基礎功能 |
| **Phase 3（進階）** | Read/Write | Read | Read（選配） | 深度分析功能 |

**權限擴充原則**：
- 遵循最小權限原則
- 按需擴充，不預先開放
- 新功能獨立的權限檢查
- 向下相容（Phase 1 功能不受影響）

---

### 12.4 功能優先級

#### 高優先級（Phase 2）
1. Web Dashboard - 提升易用性
2. 自動解封機制 - 減少管理負擔
3. GeoIP 顯示 - 增強情報能力

#### 中優先級（Phase 2-3）
1. 多台 FortiGate 支援 - 企業需求
2. 統計報表 - 管理層需求
3. 日誌 API 整合 - 補充 Syslog

#### 低優先級（Phase 3）
1. 機器學習 - 技術挑戰高
2. 其他防火牆品牌 - 市場需求待評估
3. SIEM 整合 - 企業特定需求

---

### 12.5 技術債務

- 改善錯誤訊息的可讀性
- 增加更多單元測試
- 完善 CI/CD Pipeline
- 效能 Profiling 與優化
- API Rate Limit 處理優化
- 分散式鎖機制改進

---

## 附錄 A：FortiGate 設定指南

### A.1 啟用 Syslog

```bash
config log syslogd setting
    set status enable
    set server "192.168.1.100"
    set port 514
end
```

### A.2 建立 API Token

```bash
config system api-user
    edit "security-bot"
        set accprofile "super_admin"
        config trusthost
            edit 1
                set ipv4-trusthost 192.168.1.0/24
            next
        end
    next
end
```

### A.3 建立封鎖 Policy

```bash
config firewall policy
    edit 100
        set name "Block-Banned-IPs"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "ban_list"  # Address Group
        set dstaddr "all"
        set action deny
        set schedule "always"
    next
end
```

---

## 附錄 B：環境變數設定

```bash
# .env 範例
FORTIGATE_HOST=192.168.1.99
FORTIGATE_TOKEN=your_api_token_here
FORTIGATE_VERIFY_SSL=false

TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
TELEGRAM_ADMIN_IDS=123456789,987654321

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

SYSLOG_HOST=0.0.0.0
SYSLOG_PORT=514
SYSLOG_PROTOCOL=udp

FAIL_THRESHOLD=3
TIME_WINDOW=600
WHITELIST=10.0.0.0/8,192.168.0.1
```

---

**文件版本歷史**:
- v1.0 (2026-02-03): 初始版本，完整系統設計

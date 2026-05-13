# FortiGate Auto-Ban System - 安全性與程式碼品質審查報告

**審查日期**: 2026-02-07
**審查範圍**: fortigate_client.py, syslog_processor.py, telegram_bot.py
**程式碼總量**: 817 行
**審查者**: Claude Code Security Review Agent

---

## 執行摘要

審查了三個核心模組共 817 行程式碼，發現 **12 個高風險問題**、**8 個中風險問題** 和 **6 個低風險問題**。主要安全性問題集中在：

1. SSL 憑證驗證被完全停用
2. 缺乏 Rate Limiting 與 DoS 防護
3. 輸入驗證不完整
4. 缺乏日誌安全性與審計機制

---

## 🔴 高風險問題（12 項）

### 1. SSL 憑證驗證完全停用

**問題描述**
- `fortigate_client.py:40` - `verify=False` 完全停用 SSL 憑證驗證
- 這使系統暴露於中間人攻擊 (MITM) 風險中

**風險等級**: 🔴 高風險

**受影響檔案**: `fortigate_client.py:39-46`

**修復建議**:
應該使用自訂 CA 憑證而非完全停用驗證：

```python
import ssl
from pathlib import Path

def __init__(self, host: str = None, token: str = None, ca_cert_path: str = None):
    self.host = host or FORTIGATE_HOST
    self.token = token or FORTIGATE_TOKEN
    self.ca_cert_path = ca_cert_path or os.getenv("FORTIGATE_CA_CERT")

    # 建立 SSL Context
    if self.ca_cert_path and Path(self.ca_cert_path).exists():
        # 使用自訂 CA 憑證
        ssl_context = ssl.create_default_context(cafile=self.ca_cert_path)
        verify = ssl_context
    elif os.getenv("FORTIGATE_VERIFY_SSL", "true").lower() == "false":
        # 開發環境：記錄警告並允許自簽憑證
        print("[WARN] SSL 憑證驗證已停用，僅適用於開發環境！")
        verify = False
    else:
        # 生產環境：使用系統 CA
        verify = True

    self.client = httpx.AsyncClient(
        verify=verify,
        timeout=30.0,
        headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    )
```

**MVP 評估**: ⏳ 可延後（內網環境可接受自簽憑證）

---

### 2. 缺乏 Rate Limiting - DoS 攻擊風險

**問題描述**
- `telegram_bot.py` - 所有指令都沒有 Rate Limiting
- 攻擊者可以快速呼叫 `/list`、`/unban` 等指令，導致 FortiGate API 超載
- `syslog_processor.py` - 沒有限制 Syslog 訊息處理速率

**風險等級**: 🔴 高風險

**受影響檔案**:
- `telegram_bot.py:129-266` (所有 cmd_* 方法)
- `syslog_processor.py:100-213`

**修復建議**: 實作簡單的 Rate Limiter

```python
from collections import defaultdict
from datetime import datetime, timedelta

class RateLimiter:
    """簡單的 Rate Limiter"""
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        """檢查是否允許請求"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.time_window)

        # 清理過期記錄
        self.requests[key] = [ts for ts in self.requests[key] if ts > cutoff]

        # 檢查是否超過限制
        if len(self.requests[key]) >= self.max_requests:
            return False

        self.requests[key].append(now)
        return True

# 使用範例
self.rate_limiter = RateLimiter(max_requests=20, time_window=60)

async def cmd_list(self, update, context):
    if not self.rate_limiter.is_allowed(f"user_{update.effective_user.id}"):
        await update.message.reply_text("[WARN] 請求過於頻繁")
        return
    # 原有邏輯...
```

**MVP 評估**: ✅ 建議修復（20 分鐘，簡單有效）

---

### 3. API Token 可能洩漏到日誌

**問題描述**
- `fortigate_client.py:166` - 錯誤訊息可能包含 API Token
- `telegram_bot.py:360` - Token 部分內容被記錄到 console

**風險等級**: 🔴 高風險

**受影響檔案**:
```python
# fortigate_client.py:166
print(f"[ERROR] Response: {response.text[:200]}")  # 可能包含 Token

# telegram_bot.py:360
print(f"\n[Bot] Token: {self.token[:10]}...{self.token[-6:]}")  # 部分洩漏
```

**修復建議**:

```python
def sanitize_error_message(text: str) -> str:
    """移除錯誤訊息中的敏感資料"""
    import re
    text = re.sub(r'Bearer\s+[\w-]+', 'Bearer [REDACTED]', text)
    text = re.sub(r'"Authorization":\s*"[^"]*"', '"Authorization": "[REDACTED]"', text)
    return text

# 使用
print(f"[ERROR] Response: {sanitize_error_message(response.text[:200])}")

# 不要記錄 Token
print(f"\n[Bot] Token: ***REDACTED*** ({len(self.token)} chars)")
```

**MVP 評估**: ⏳ 可延後（內部測試環境）

---

### 4. 命令注入風險 - IP 字串未完整驗證

**問題描述**
- `fortigate_client.py:148` - IP 字串直接用於建立 Address 名稱，未完整驗證
- `telegram_bot.py:239-240` - IP 驗證過於簡單，可能繞過

**風險等級**: 🔴 高風險

**受影響檔案**:
```python
# fortigate_client.py:148
address_name = f"ban_{ip.replace('.', '_')}"  # IP 未完整驗證

# telegram_bot.py:239-240
parts = ip.split('.')
if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
    # 簡單驗證，可能繞過
```

**修復建議**: 使用標準庫 `ipaddress` 模組

```python
import ipaddress

def validate_ip_address(ip: str) -> bool:
    """嚴格驗證 IP 位址格式"""
    try:
        addr = ipaddress.ip_address(ip)

        # 可選：拒絕特殊 IP 範圍
        if addr.is_loopback or addr.is_multicast or addr.is_reserved:
            print(f"[WARN] Rejected special IP: {ip}")
            return False

        return True
    except ValueError:
        return False

# 在所有使用 IP 的地方加入驗證
if not validate_ip_address(ip):
    print(f"[ERROR] Invalid IP address: {ip}")
    return False
```

**MVP 評估**: ✅ **必須修復**（15 分鐘，防止格式錯誤）

---

### 5. 正則表達式 ReDoS 風險

**問題描述**
- `syslog_processor.py:152-154` - 正則表達式可能造成 ReDoS 攻擊

**風險等級**: 🔴 高風險

**受影響檔案**: `syslog_processor.py:152-154`

**修復建議**: 預編譯正則表達式並加入長度限制

```python
import re

class SyslogProcessor:
    def __init__(self, ...):
        # 預編譯正則表達式
        self.ip_patterns = [
            re.compile(r'src=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
            re.compile(r'srcip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
            re.compile(r'login failed from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'),
        ]
        self.max_message_length = 2048

    def _parse_ip_from_syslog(self, message: str) -> Optional[str]:
        # 長度限制（防止 ReDoS）
        if len(message) > self.max_message_length:
            message = message[:self.max_message_length]

        # 使用預編譯 Pattern
        for pattern in self.ip_patterns:
            match = pattern.search(message)
            if match:
                ip = match.group(1)
                if validate_ip_address(ip):
                    return ip
        return None
```

**MVP 評估**: ⏳ 可延後（內網環境風險較低）

---

### 6. UDP Syslog Server 缺乏來源驗證

**問題描述**
- `syslog_processor.py:72-88` - UDP Server 接受來自任何來源的訊息
- 攻擊者可以偽造 Syslog 訊息觸發惡意封鎖

**風險等級**: 🔴 高風險

**受影響檔案**: `syslog_processor.py:84-88`

**修復建議**: 加入來源 IP 白名單

```python
class SyslogProcessor:
    def __init__(
        self,
        fortigate_client,
        notifier: Optional[Callable] = None,
        threshold: int = 3,
        time_window: int = 600,
        whitelist: Optional[list] = None,
        allowed_syslog_sources: Optional[list] = None  # 新增
    ):
        self.allowed_syslog_sources = set(allowed_syslog_sources or [])
        if not self.allowed_syslog_sources:
            print("[WARN] No Syslog source whitelist - accepting from all sources!")

    async def handle_syslog(self, message: str, addr: tuple):
        source_ip, source_port = addr

        # 驗證來源
        if self.allowed_syslog_sources and source_ip not in self.allowed_syslog_sources:
            print(f"[WARN] Rejected Syslog from unauthorized source: {source_ip}")
            return

        # 原有邏輯...
```

環境變數配置：
```bash
SYSLOG_ALLOWED_SOURCES=35.189.179.171,127.0.0.1
```

**MVP 評估**: ✅ 建議修復（15 分鐘，簡單有效）

---

### 7. Telegram Admin 權限檢查不完整

**問題描述**
- `telegram_bot.py:97-99` - `is_admin` 方法過於簡單
- 沒有考慮群組管理員、Bot API 提供的權限檢查

**風險等級**: 🔴 高風險

**受影響檔案**: `telegram_bot.py:97-99`

**修復建議**: 使用 Telegram Bot API 的群組管理員檢查

```python
async def is_admin(self, update: Update) -> bool:
    """增強的管理員檢查"""
    user_id = update.effective_user.id

    # 1. 檢查靜態管理員列表
    if user_id in self.admin_ids:
        return True

    # 2. 檢查群組管理員（如果在群組中）
    if update.effective_chat.type in ["group", "supergroup"]:
        try:
            member = await update.effective_chat.get_member(user_id)
            if member.status in ["creator", "administrator"]:
                return True
        except Exception as e:
            print(f"[ERROR] Failed to check group admin status: {e}")

    return False
```

**MVP 評估**: ⏳ 可延後（僅個人使用）

---

### 8. 缺乏輸入長度限制

**問題描述**
- `fortigate_client.py:136-156` - comment 參數沒有長度限制
- `syslog_processor.py:100-139` - Syslog 訊息沒有大小限制

**風險等級**: 🔴 高風險

**修復建議**:

```python
# fortigate_client.py
async def block_ip(self, ip: str, comment: str) -> bool:
    # 限制 comment 長度（FortiGate 限制 255 字元）
    if len(comment) > 255:
        comment = comment[:252] + "..."

    # 清理特殊字元
    comment = comment.replace('\n', ' ').replace('\r', ' ')
    # ...

# syslog_processor.py
async def handle_syslog(self, message: str, addr: tuple):
    # 長度限制（RFC 5424 建議最大 2048 bytes）
    if len(message) > 2048:
        message = message[:2048]
    # ...
```

**MVP 評估**: ⏳ 可延後（內網環境風險較低）

---

### 9. 缺乏 CSRF 保護機制

**問題描述**
- `telegram_bot.py` - 所有危險操作（`/unban`）沒有二次確認機制

**風險等級**: 🔴 高風險

**修復建議**: 使用 Telegram InlineKeyboard 實作二次確認

```python
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import CallbackQueryHandler

async def cmd_unban(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... 驗證邏輯 ...

    # 建立確認按鈕
    keyboard = [[
        InlineKeyboardButton("✓ 確認", callback_data=f"unban_confirm_{ip}"),
        InlineKeyboardButton("✗ 取消", callback_data=f"unban_cancel_{ip}")
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"確認要解除封鎖 IP: `{ip}` 嗎？",
        reply_markup=reply_markup,
        parse_mode="Markdown"
    )

async def handle_unban_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    action, status, ip = query.data.split("_", 2)

    if status == "cancel":
        await query.edit_message_text(f"已取消解除封鎖 {ip}")
        return

    # 執行解除封鎖...
```

**MVP 評估**: ⏳ 可延後（僅個人使用）

---

### 10. 敏感資料記錄到 Console

**問題描述**
- 多處將敏感資料（IP、Token、Host）記錄到 console
- 生產環境可能洩漏敏感資訊

**風險等級**: 🔴 高風險

**受影響檔案**:
- `telegram_bot.py:204, 360-363`
- `fortigate_client.py:85-89`
- `syslog_processor.py:134`

**修復建議**: 實作安全的日誌系統

```python
import logging

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
PRODUCTION_MODE = os.getenv("PRODUCTION", "false").lower() == "true"

logger = logging.getLogger(__name__)

def safe_log_ip(ip: str) -> str:
    """安全記錄 IP（生產環境遮罩）"""
    if PRODUCTION_MODE:
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.***.**" if len(parts) == 4 else "***"
    return ip

# 使用
logger.info(f"IP {safe_log_ip(ip)} failed login")
```

**MVP 評估**: ⏳ 可延後（內部測試環境）

---

### 11. 記憶體洩漏風險 - 無限增長的計數器

**問題描述**
- `syslog_processor.py:66` - `failure_counter` 字典可能無限增長
- 沒有清理機制，長期運行會導致記憶體耗盡

**風險等級**: 🔴 高風險

**受影響檔案**: `syslog_processor.py:66`

**修復建議**: 加入定期清理機制

```python
class SyslogProcessor:
    def __init__(self, ...):
        self.failure_counter = defaultdict(list)
        self.max_tracked_ips = 10000  # 最多追蹤 10000 個 IP
        self.cleanup_interval = 3600  # 每小時清理一次

    async def start_server(self, host: str = '0.0.0.0', port: int = 5141):
        # ... 原有程式碼 ...
        # 啟動定期清理任務
        asyncio.create_task(self._periodic_cleanup())

    async def _periodic_cleanup(self):
        """定期清理過期記錄"""
        while True:
            await asyncio.sleep(self.cleanup_interval)

            now = datetime.now()
            cutoff = now - timedelta(seconds=self.time_window)

            # 清理過期記錄
            for ip in list(self.failure_counter.keys()):
                self.failure_counter[ip] = [
                    ts for ts in self.failure_counter[ip] if ts > cutoff
                ]
                if not self.failure_counter[ip]:
                    del self.failure_counter[ip]

            # 檢查總數限制
            if len(self.failure_counter) > self.max_tracked_ips:
                # 保留最近更新的 IP，移除最舊的 10%
                sorted_ips = sorted(
                    self.failure_counter.items(),
                    key=lambda x: max(x[1]) if x[1] else datetime.min
                )
                remove_count = len(sorted_ips) // 10
                for ip, _ in sorted_ips[:remove_count]:
                    del self.failure_counter[ip]
```

**MVP 評估**: ✅ **必須修復**（30 分鐘，影響長期穩定性）

---

### 12. 缺乏異常處理的資源清理

**問題描述**
- `fortigate_client.py:48-50` - `close()` 方法可能不會被呼叫
- 缺乏 context manager 支援

**風險等級**: 🔴 高風險

**修復建議**: 實作 context manager

```python
class FortiGateClient:
    async def __aenter__(self):
        """Context manager 進入"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager 退出 - 確保資源清理"""
        await self.close()

    async def close(self):
        """關閉 HTTP Client 連線"""
        if self.client:
            await self.client.aclose()
            self.client = None

# 使用方式
async with FortiGateClient() as client:
    ips = await client.list_banned_ips()
    # ... 其他操作 ...
# 自動關閉連線
```

**MVP 評估**: ✅ 建議修復（15 分鐘，確保資源正確釋放）

---

## 🟡 中風險問題（8 項）

### 13. 缺乏操作審計日誌
- 無法追蹤誰在何時執行了什麼操作
- **MVP 評估**: ⏳ 可延後（正式環境前加入）

### 14. 白名單機制不完整
- 不支援 CIDR 網段、沒有動態更新機制
- **MVP 評估**: ⏳ 可延後

### 15. 缺乏連線重試機制
- 網路錯誤時沒有重試機制
- **MVP 評估**: ⏳ 可延後

### 16. 環境變數未驗證
- 環境變數讀取後未驗證，可能導致運行時錯誤
- **MVP 評估**: ✅ **必須修復**（10 分鐘，避免配置錯誤）

### 17. 缺乏效能監控
- 沒有追蹤 API 回應時間、錯誤率等指標
- **MVP 評估**: ⏳ 可延後（正式環境前加入）

### 18. Telegram Bot 缺乏錯誤訊息本地化
- 錯誤訊息混用中英文，格式不一致
- **MVP 評估**: ⏳ 可延後

### 19. 缺乏健康檢查端點
- 無法監控系統是否正常運行
- **MVP 評估**: ⏳ 可延後

### 20. Mock Client 與真實 Client 介面不一致
- 可能導致切換到真實 API 時出現錯誤
- **MVP 評估**: ⏳ 可延後（已測試過整合）

---

## 🔵 低風險問題（6 項）

21. Type Hints 不完整
22. 缺乏單元測試
23. 硬編碼的設定值
24. 缺乏版本資訊
25. 程式碼重複
26. 缺乏 Graceful Shutdown

**MVP 評估**: 全部可延後

---

## 📊 MVP 階段修復優先順序

### ✅ 必須修復（總計 ~1.5 小時）

| 問題 | 優先級 | 時間 | 理由 |
|------|--------|------|------|
| #16 環境變數驗證 | P0 | 10 分鐘 | 避免配置錯誤 |
| #4 IP 驗證完整性 | P0 | 15 分鐘 | 防止格式錯誤 |
| #12 資源清理 Context Manager | P0 | 15 分鐘 | 確保連線關閉 |
| #11 記憶體洩漏保護 | P0 | 30 分鐘 | 長期穩定運行 |
| #2 基礎 Rate Limiting | P1 | 20 分鐘 | 防止意外洪水 |
| #6 Syslog 來源白名單 | P1 | 15 分鐘 | 防止偽造 |

**總時間**: ~1.5 小時

### ⏳ 正式環境前修復

- #1 SSL 憑證驗證
- #3 Token 日誌清理
- #7 Admin 權限檢查
- #9 CSRF 保護
- #10 敏感資料記錄
- #13 操作審計日誌

### ❌ 可延後或不需要

- #5 ReDoS 防護（內網環境）
- #8 輸入長度限制（內網環境）
- #14-26 中低風險問題

---

## 📋 修復檢查清單

### Phase 1: MVP 基礎防護（必須完成）

- [ ] 環境變數驗證 (#16)
  - [ ] 檢查必要變數存在
  - [ ] 驗證變數格式
  - [ ] 啟動失敗時明確錯誤訊息

- [ ] IP 驗證 (#4)
  - [ ] 使用 `ipaddress` 模組
  - [ ] 拒絕特殊 IP（loopback, multicast, reserved）
  - [ ] 在所有使用 IP 的地方加入驗證

- [ ] 資源清理 (#12)
  - [ ] FortiGateClient 實作 `__aenter__` / `__aexit__`
  - [ ] 確保 `close()` 在異常時也會執行

- [ ] 記憶體洩漏防護 (#11)
  - [ ] 設定 `max_tracked_ips` 限制
  - [ ] 實作定期清理機制
  - [ ] 清理過期時間戳

- [ ] Rate Limiting (#2)
  - [ ] 實作 SimpleRateLimiter 類別
  - [ ] Bot 指令加入 Rate Limiting
  - [ ] Syslog 處理加入全域限制

- [ ] Syslog 來源驗證 (#6)
  - [ ] 加入 `allowed_syslog_sources` 參數
  - [ ] 從環境變數讀取白名單
  - [ ] 拒絕未授權來源

### Phase 2: 正式環境準備（上線前完成）

- [ ] SSL 憑證驗證 (#1)
- [ ] Token 日誌清理 (#3)
- [ ] Admin 權限增強 (#7)
- [ ] CSRF 保護 (#9)
- [ ] 審計日誌 (#13)

---

## 🛠️ 最佳實踐建議

1. **使用 Pydantic 進行設定驗證**
2. **使用 structlog 進行結構化日誌**
3. **實作 Circuit Breaker 模式**（防止 API 故障時持續重試）
4. **加入 Prometheus 監控**（追蹤效能指標）
5. **使用 Python Dataclasses**（定義資料結構）

---

## 📝 結論

### MVP 階段重點

1. ✅ **功能穩定性優先**（記憶體洩漏、環境驗證）
2. ✅ **簡單有效的防護**（IP 驗證、Rate Limiting）
3. ❌ **不要過度設計**（Circuit Breaker、Prometheus）

### 建議行動方案

**快速修復套餐**（1.5 小時）：
- 環境驗證 + IP 驗證 + 資源清理 = 40 分鐘
- 記憶體保護 = 30 分鐘
- Rate Limiting + Syslog 白名單 = 35 分鐘

完成後即可進行 MVP 部署測試，其他問題可在正式環境前逐步修復。

---

**文件版本**: 1.0
**最後更新**: 2026-02-07
**下次審查**: 正式環境部署前

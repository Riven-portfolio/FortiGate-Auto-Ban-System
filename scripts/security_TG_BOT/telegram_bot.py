"""
FortiGate Security Telegram Bot
支援 Mock 和真實 FortiGate API Client
"""
import asyncio
import os
from datetime import datetime
from typing import List, Optional
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters
)

# 載入環境變數
load_dotenv("../.env")

# 設定
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_ADMIN_IDS = [int(id.strip()) for id in os.getenv("TELEGRAM_ADMIN_IDS", "").split(",") if id.strip()]
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
USE_MOCK = os.getenv("USE_MOCK", "false").lower() == "true"  # 是否使用 Mock Client

# 導入真實 FortiGate Client
try:
    from fortigate_client import FortiGateClient
    FORTIGATE_CLIENT_AVAILABLE = True
except ImportError:
    FORTIGATE_CLIENT_AVAILABLE = False
    print("[WARN] FortiGateClient 無法導入，將使用 Mock Client")


class MockFortiGateClient:
    """模擬 FortiGate API Client（開發測試用）"""

    def __init__(self):
        # 模擬黑名單資料
        self.banned_ips = {
            "192.168.1.100": {
                "banned_at": "2026-02-04 10:30:25",
                "reason": "3 failed VPN login attempts",
                "comment": "Auto-banned by security bot"
            },
            "203.0.113.45": {
                "banned_at": "2026-02-04 14:20:10",
                "reason": "3 failed SSH login attempts",
                "comment": "Auto-banned by security bot"
            }
        }

    async def list_banned_ips(self) -> List[str]:
        """列出所有被封鎖的 IP"""
        return list(self.banned_ips.keys())

    async def unblock_ip(self, ip: str) -> bool:
        """解除封鎖"""
        if ip in self.banned_ips:
            del self.banned_ips[ip]
            return True
        return False

    async def get_ip_info(self, ip: str) -> Optional[dict]:
        """取得 IP 詳細資訊"""
        return self.banned_ips.get(ip)

    async def block_ip(self, ip: str, comment: str) -> bool:
        """封鎖 IP（測試用）"""
        self.banned_ips[ip] = {
            "banned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": "Manual ban for testing",
            "comment": comment
        }
        return True


class SecurityBot:
    """FortiGate Security Bot"""

    def __init__(self, token: str, admin_ids: List[int], fortigate_client=None):
        self.token = token
        self.admin_ids = admin_ids
        self.fortigate = fortigate_client or MockFortiGateClient()
        self.app = None

        # 統計資料（開發用）
        self.stats = {
            "total_bans": 2,
            "today_bans": 1,
            "total_unbans": 0,
            "bot_start_time": datetime.now()
        }

    def is_admin(self, user_id: int) -> bool:
        """檢查是否為管理員"""
        return user_id in self.admin_ids

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """啟動指令"""
        user = update.effective_user

        message = f"""
👋 歡迎使用 **FortiGate Security Bot**

🤖 **功能說明**

📋 **查詢指令**
/list - 列出所有黑名單 IP
/stats - 顯示系統統計資料
/status - 顯示系統狀態

⚙️ **管理指令** (僅管理員)
/unban <IP> - 解除指定 IP 的封鎖
/test <IP> - 測試封鎖功能

💡 **關於此 Bot**
自動監控 FortiGate 登入失敗事件
達到閾值（3次/10分鐘）自動封鎖 IP
實時發送 Telegram 通知

👤 您的 User ID: `{user.id}`
{'✅ 您是管理員' if self.is_admin(user.id) else '⚠️ 您不是管理員'}
"""
        await update.message.reply_text(message, parse_mode="Markdown")

    async def cmd_list(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """列出黑名單"""
        ips = await self.fortigate.list_banned_ips()

        if not ips:
            await update.message.reply_text("✅ 目前無封鎖 IP")
            return

        # 建立黑名單訊息
        message = f"🚫 **目前黑名單** ({len(ips)} 個)\n\n"

        for idx, ip in enumerate(ips, 1):
            info = await self.fortigate.get_ip_info(ip)
            message += f"{idx}. `{ip}`\n"
            if info:
                # 真實 API：使用 comment 欄位
                # Mock API：使用 banned_at 和 reason 欄位
                if 'comment' in info:
                    # 真實 FortiGate API
                    comment = info.get('comment', 'No comment')
                    message += f"   📝 {comment}\n"
                else:
                    # Mock Client
                    message += f"   ⏰ {info.get('banned_at', 'Unknown')}\n"
                    message += f"   📝 {info.get('reason', 'Unknown')}\n"
            message += "\n"

        message += f"\n💡 使用 `/unban <IP>` 解除封鎖"

        await update.message.reply_text(message, parse_mode="Markdown")

    async def cmd_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """顯示統計資料"""
        uptime = datetime.now() - self.stats["bot_start_time"]
        uptime_str = str(uptime).split('.')[0]  # 移除微秒

        current_bans = len(await self.fortigate.list_banned_ips())

        message = f"""
📊 **系統統計**

🚫 **封鎖統計**
• 目前封鎖數: {current_bans}
• 累計封鎖數: {self.stats['total_bans']}
• 今日封鎖數: {self.stats['today_bans']}
• 累計解封數: {self.stats['total_unbans']}

⚙️ **系統設定**
• 失敗閾值: 3 次
• 時間窗口: 10 分鐘
• 白名單數量: 2 個網段

⏱️ **運行時間**
• Bot 啟動時間: {self.stats['bot_start_time'].strftime('%Y-%m-%d %H:%M:%S')}
• 已運行: {uptime_str}
"""
        await update.message.reply_text(message, parse_mode="Markdown")

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """顯示系統狀態"""
        # 模擬檢查各元件狀態
        fortigate_status = "🟢 正常"
        redis_status = "🟡 未連線（開發模式）"
        syslog_status = "🟡 未啟動（開發模式）"

        message = f"""
🔍 **系統狀態**

**核心元件**
• FortiGate API: {fortigate_status}
• Redis Server: {redis_status}
• Syslog Server: {syslog_status}
• Telegram Bot: 🟢 正常

**FortiGate 資訊**
• Host: `{os.getenv('FORTIGATE_HOST', 'Not configured')}`
• API Token: {'✅ 已設定' if os.getenv('FORTIGATE_TOKEN') else '❌ 未設定'}

**Telegram 資訊**
• Chat ID: `{TELEGRAM_CHAT_ID}`
• 管理員數量: {len(self.admin_ids)}

💡 **開發模式**
目前使用 Mock 資料進行測試
完成後將連接真實 FortiGate API
"""
        await update.message.reply_text(message, parse_mode="Markdown")

    async def cmd_unban(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """解除封鎖 (僅管理員)"""
        user_id = update.effective_user.id

        # 檢查管理員權限
        if not self.is_admin(user_id):
            await update.message.reply_text("⛔ 權限不足：此指令僅限管理員使用")
            return

        # 檢查參數
        if not context.args:
            await update.message.reply_text(
                "❌ 用法錯誤\n\n"
                "正確用法: `/unban <IP>`\n"
                "範例: `/unban 192.168.1.100`",
                parse_mode="Markdown"
            )
            return

        ip = context.args[0]

        # 驗證 IP 格式
        import ipaddress as _ipaddress
        try:
            _ipaddress.ip_address(ip)
        except ValueError:
            await update.message.reply_text(f"[ERROR] IP 格式錯誤: {ip}", parse_mode="Markdown")
            return

        # 執行解除封鎖
        success = await self.fortigate.unblock_ip(ip)

        if success:
            self.stats['total_unbans'] += 1
            message = f"""
✅ **解除封鎖成功**

📍 IP 位址: `{ip}`
👤 操作者: {update.effective_user.first_name}
🕐 解除時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

IP 已從黑名單移除
"""
            await update.message.reply_text(message, parse_mode="Markdown")
        else:
            await update.message.reply_text(
                f"❌ 解除封鎖失敗\n\n"
                f"IP `{ip}` 不在黑名單中\n"
                f"使用 /list 查看目前黑名單",
                parse_mode="Markdown"
            )

    async def cmd_test(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """測試封鎖功能 (僅管理員)"""
        user_id = update.effective_user.id

        if not self.is_admin(user_id):
            await update.message.reply_text("⛔ 權限不足：此指令僅限管理員使用")
            return

        if not context.args:
            await update.message.reply_text(
                "❌ 用法錯誤\n\n"
                "正確用法: `/test <IP>`\n"
                "範例: `/test 198.51.100.1`",
                parse_mode="Markdown"
            )
            return

        ip = context.args[0]

        # 測試封鎖
        success = await self.fortigate.block_ip(ip, "Test ban")

        if success:
            # 發送封鎖通知（測試）
            await self.send_ban_notification(
                ip=ip,
                fail_count=3,
                source_system="Test",
                event_type="test"
            )
            await update.message.reply_text(
                f"✅ 測試成功\n\n"
                f"已模擬封鎖 IP: `{ip}`\n"
                f"並發送通知到此 Chat",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(f"❌ 測試失敗", parse_mode="Markdown")

    async def send_ban_notification(self, ip: str, fail_count: int, source_system: str, event_type: str):
        """發送封鎖通知"""
        if not TELEGRAM_CHAT_ID:
            print("[WARN] TELEGRAM_CHAT_ID not set, cannot send notification")
            return

        blacklist_count = len(await self.fortigate.list_banned_ips())

        message = f"""[ALERT] IP 已自動封鎖

IP 位址: {ip}
失敗次數: {fail_count} 次 (10 分鐘內)
封鎖時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
來源系統: {source_system}
事件類型: {event_type}

目前黑名單總數: {blacklist_count}

使用 /list 查看完整黑名單
使用 /unban {ip} 解除封鎖"""

        try:
            await self.app.bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=message
            )
            print(f"[OK] Notification sent to Chat ID: {TELEGRAM_CHAT_ID}")
        except Exception as e:
            print(f"[ERROR] Failed to send notification: {e}")

    async def handle_unknown(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """處理未知指令"""
        message = (
            "❓ 未知指令\n\n"
            "使用 /start 查看可用指令"
        )
        await update.message.reply_text(message)

    def start(self):
        """啟動 Bot"""
        if not self.token:
            print("[ERROR] TELEGRAM_BOT_TOKEN not set")
            print("請在 .env 檔案中設定 Bot Token")
            return

        # 判斷使用的 Client 類型
        client_type = "Mock Client" if isinstance(self.fortigate, MockFortiGateClient) else "Real FortiGate API"

        print("\n" + "="*60)
        print("  FortiGate Security Telegram Bot")
        print("="*60)
        print(f"\n[Bot] Token: {self.token[:10]}...{self.token[-6:]}")
        print(f"[Admin] IDs: {self.admin_ids}")
        print(f"[Chat] ID: {TELEGRAM_CHAT_ID}")
        print(f"\n[FortiGate] {client_type}")
        print("\nStarting...\n")

        # 建立 Application
        self.app = ApplicationBuilder().token(self.token).build()

        # 註冊指令
        self.app.add_handler(CommandHandler("start", self.cmd_start))
        self.app.add_handler(CommandHandler("list", self.cmd_list))
        self.app.add_handler(CommandHandler("stats", self.cmd_stats))
        self.app.add_handler(CommandHandler("status", self.cmd_status))
        self.app.add_handler(CommandHandler("unban", self.cmd_unban))
        self.app.add_handler(CommandHandler("test", self.cmd_test))

        # 未知指令處理
        self.app.add_handler(MessageHandler(filters.COMMAND, self.handle_unknown))

        print("[OK] Bot Started!")
        print("\n[Commands]")
        print("   /start  - Show welcome message")
        print("   /list   - List banned IPs")
        print("   /stats  - Show statistics")
        print("   /status - System status")
        print("   /unban  - Unban IP (admin only)")
        print("   /test   - Test ban notification (admin only)")
        print("\nPress Ctrl+C to stop\n")

        # 啟動輪詢
        self.app.run_polling()


def main():
    """主程式"""
    # 選擇 FortiGate Client
    if USE_MOCK or not FORTIGATE_CLIENT_AVAILABLE:
        print("[INFO] 使用 Mock FortiGate Client（開發模式）")
        fortigate_client = MockFortiGateClient()
    else:
        print("[INFO] 使用真實 FortiGate API Client")
        fortigate_client = FortiGateClient()

    # 建立 Bot
    bot = SecurityBot(
        token=TELEGRAM_BOT_TOKEN,
        admin_ids=TELEGRAM_ADMIN_IDS,
        fortigate_client=fortigate_client
    )
    bot.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[STOP] Bot stopped")

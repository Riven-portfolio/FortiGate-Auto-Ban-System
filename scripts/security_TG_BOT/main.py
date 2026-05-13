"""
FortiGate Auto-Ban System - Main Entry Point
整合 FortiGate Client, Syslog Processor, Telegram Bot
"""
import asyncio
import os
import signal
from dotenv import load_dotenv

# 載入環境變數
load_dotenv("../.env")

# 導入三個模組
from fortigate_client import FortiGateClient
from syslog_processor import SyslogProcessor
from telegram_bot import SecurityBot, MockFortiGateClient


class AutoBanSystem:
    """FortiGate 自動封鎖系統"""

    def __init__(self):
        self.fortigate_client = None
        self.syslog_processor = None
        self.telegram_bot = None
        self.running = True

        # 從環境變數讀取設定
        self.use_real_fortigate = os.getenv("USE_REAL_FORTIGATE", "false").lower() == "true"
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_admin_ids = [
            int(id.strip()) for id in os.getenv("TELEGRAM_ADMIN_IDS", "").split(",") if id.strip()
        ]
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")

    async def start(self):
        """啟動所有元件"""
        print("\n" + "=" * 60)
        print("  FortiGate Auto-Ban System")
        print("=" * 60)
        print()

        # 1. 初始化 FortiGate Client
        print("[1/3] Initializing FortiGate Client...")
        if self.use_real_fortigate:
            print("  [MODE] Using REAL FortiGate API")
            print("  [WARN] *** IPs WILL BE ACTUALLY BLOCKED ***")
            self.fortigate_client = FortiGateClient()
        else:
            print("  [MODE] Using Mock FortiGate Client (Safe Mode)")
            self.fortigate_client = MockFortiGateClient()
        print("  [OK] FortiGate Client initialized\n")

        # 2. 初始化 Telegram Bot
        print("[2/3] Initializing Telegram Bot...")
        self.telegram_bot = SecurityBot(
            token=self.telegram_token,
            admin_ids=self.telegram_admin_ids,
            fortigate_client=self.fortigate_client
        )
        # 手動建立 Application（不使用 start() 方法）
        await self.setup_telegram_bot()
        print("  [OK] Telegram Bot initialized\n")

        # 3. 初始化 Syslog Processor
        print("[3/3] Initializing Syslog Processor...")
        whitelist = [
            ip.strip()
            for ip in os.getenv("WHITELIST", "").split(",")
            if ip.strip()
        ]
        self.syslog_processor = SyslogProcessor(
            fortigate_client=self.fortigate_client,
            notifier=self.telegram_notification,  # 使用整合的通知函數
            threshold=int(os.getenv("FAIL_THRESHOLD", "3")),
            time_window=int(os.getenv("TIME_WINDOW", "600")),
            whitelist=whitelist,
        )
        print(f"  [INFO] Whitelist: {whitelist if whitelist else 'empty'}")
        print("  [OK] Syslog Processor initialized\n")

        # 註冊信號處理（Graceful Shutdown）
        try:
            loop = asyncio.get_event_loop()
            # Windows 只支援 SIGINT (Ctrl+C)
            loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(self.shutdown()))
            # Linux/Mac 支援 SIGTERM
            if hasattr(signal, 'SIGTERM'):
                loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.create_task(self.shutdown()))
        except NotImplementedError:
            # Windows 的某些情況可能不支援
            pass

        # 啟動所有元件
        print("=" * 60)
        print("  Starting All Components")
        print("=" * 60)
        print()

        # 啟動 Syslog Server
        print("[Syslog] Starting UDP server on port 5141...")
        await self.syslog_processor.start_server(host='0.0.0.0', port=5141)
        print("[Syslog] Server started successfully\n")

        # 啟動 Telegram Bot
        print("[Telegram] Starting bot...")
        await self.telegram_bot.app.initialize()
        await self.telegram_bot.app.start()
        await self.telegram_bot.app.updater.start_polling()
        print("[Telegram] Bot started successfully\n")

        print("=" * 60)
        print("  System Running")
        print("=" * 60)
        print()
        print(f"[FortiGate] Mode: {'REAL API' if self.use_real_fortigate else 'Mock (Safe)'}")
        print(f"[Syslog] Listening on: 0.0.0.0:5141")
        print(f"[Telegram] Chat ID: {self.telegram_chat_id}")
        print(f"[Telegram] Admins: {self.telegram_admin_ids}")
        print()
        print("[Commands]")
        print("   /start  - Show welcome message")
        print("   /list   - List banned IPs")
        print("   /stats  - Show statistics")
        print("   /status - System status")
        print("   /unban  - Unban IP (admin only)")
        print("   /test   - Test ban notification (admin only)")
        print()
        print("Press Ctrl+C to stop")
        print()

        # 保持運行直到收到 Ctrl+C
        try:
            while self.running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            print("\n[INFO] Shutdown signal received")
        finally:
            await self.shutdown()

    async def setup_telegram_bot(self):
        """設定 Telegram Bot（非阻塞方式）"""
        from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters

        if not self.telegram_token:
            print("[ERROR] TELEGRAM_BOT_TOKEN not set")
            return

        # 建立 Application
        self.telegram_bot.app = ApplicationBuilder().token(self.telegram_token).build()

        # 註冊指令
        self.telegram_bot.app.add_handler(CommandHandler("start", self.telegram_bot.cmd_start))
        self.telegram_bot.app.add_handler(CommandHandler("list", self.telegram_bot.cmd_list))
        self.telegram_bot.app.add_handler(CommandHandler("stats", self.telegram_bot.cmd_stats))
        self.telegram_bot.app.add_handler(CommandHandler("status", self.telegram_bot.cmd_status))
        self.telegram_bot.app.add_handler(CommandHandler("unban", self.telegram_bot.cmd_unban))
        self.telegram_bot.app.add_handler(CommandHandler("test", self.telegram_bot.cmd_test))
        self.telegram_bot.app.add_handler(MessageHandler(filters.COMMAND, self.telegram_bot.handle_unknown))

    async def telegram_notification(self, ip: str, fail_count: int, source_system: str, event_type: str):
        """
        Telegram 通知函數（整合版）
        當 Syslog Processor 觸發自動封鎖時，發送 Telegram 通知
        """
        print(f"\n[DEBUG] telegram_notification called:")
        print(f"  - IP: {ip}")
        print(f"  - Fail Count: {fail_count}")
        print(f"  - Source: {source_system}")
        print(f"  - Event: {event_type}")
        print(f"  - Chat ID: {self.telegram_chat_id}")
        print(f"  - Bot exists: {self.telegram_bot is not None}")
        print(f"  - App exists: {self.telegram_bot.app is not None if self.telegram_bot else False}")

        if not self.telegram_chat_id:
            print("[WARN] TELEGRAM_CHAT_ID not set, cannot send notification")
            return

        # 使用 Telegram Bot 的通知方法
        if self.telegram_bot and self.telegram_bot.app:
            try:
                await self.telegram_bot.send_ban_notification(
                    ip=ip,
                    fail_count=fail_count,
                    source_system=source_system,
                    event_type=event_type
                )
                print("[DEBUG] Notification sent successfully")
            except Exception as e:
                print(f"[ERROR] Failed to send notification: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("[ERROR] Telegram Bot or App not initialized")

    async def shutdown(self):
        """優雅關閉系統"""
        if not self.running:
            return

        print("\n" + "=" * 60)
        print("  Shutting Down")
        print("=" * 60)

        self.running = False

        # 1. 停止 Telegram Bot
        if self.telegram_bot and self.telegram_bot.app:
            print("\n[1/3] Stopping Telegram Bot...")
            try:
                await self.telegram_bot.app.updater.stop()
                await self.telegram_bot.app.stop()
                await self.telegram_bot.app.shutdown()
                print("  [OK] Telegram Bot stopped")
            except Exception as e:
                print(f"  [WARN] Error stopping bot: {e}")

        # 2. 停止 Syslog Server
        if self.syslog_processor:
            print("\n[2/3] Stopping Syslog Processor...")
            try:
                await self.syslog_processor.stop_server()
                print("  [OK] Syslog Processor stopped")
            except Exception as e:
                print(f"  [WARN] Error stopping processor: {e}")

        # 3. 關閉 FortiGate Client
        if self.fortigate_client and hasattr(self.fortigate_client, 'close'):
            print("\n[3/3] Closing FortiGate Client...")
            try:
                await self.fortigate_client.close()
                print("  [OK] FortiGate Client closed")
            except Exception as e:
                print(f"  [WARN] Error closing client: {e}")

        print("\n" + "=" * 60)
        print("  Shutdown Complete")
        print("=" * 60)
        print()


async def main():
    """主程式"""
    system = AutoBanSystem()
    await system.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Fatal error: {e}")
        import traceback
        traceback.print_exc()

"""
FortiGate Syslog Processor
接收並處理 FortiGate Syslog 訊息，統計失敗次數並觸發自動封鎖
"""
import asyncio
import ipaddress
import re
from datetime import datetime, timedelta
from typing import Optional, Callable
from collections import defaultdict


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """UDP Server Protocol for Syslog"""

    def __init__(self, handler):
        self.handler = handler
        super().__init__()

    def datagram_received(self, data, addr):
        """收到 UDP 封包時的回調"""
        try:
            message = data.decode('utf-8')
            # 使用 asyncio.create_task 來處理異步邏輯
            asyncio.create_task(self.handler(message, addr))
        except Exception as e:
            print(f"[ERROR] Failed to process syslog from {addr}: {e}")


class SyslogProcessor:
    """
    Syslog 處理器

    職責：
    1. 接收 FortiGate Syslog (UDP 514)
    2. 解析登入失敗事件
    3. 統計失敗次數（時間窗口內）
    4. 達到閾值時觸發自動封鎖
    5. 發送通知
    """

    def __init__(
        self,
        fortigate_client,
        notifier: Optional[Callable] = None,
        threshold: int = 3,
        time_window: int = 600,
        whitelist: Optional[list] = None
    ):
        """
        初始化 Syslog Processor

        Args:
            fortigate_client: FortiGate API Client (用於封鎖操作)
            notifier: 通知函數 (接收 ip, count, event_type 參數)
            threshold: 失敗次數閾值 (預設 3 次)
            time_window: 時間窗口 (秒，預設 600 = 10分鐘)
            whitelist: 白名單 IP 列表
        """
        self.fortigate = fortigate_client
        self.notifier = notifier
        self.threshold = threshold
        self.time_window = time_window

        # 白名單：支援精確 IP 和 CIDR 網段
        self.whitelist_ips = set()
        self.whitelist_networks = []
        for entry in (whitelist or []):
            try:
                self.whitelist_networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self.whitelist_ips.add(entry)

        # 失敗計數器: {IP: [timestamp1, timestamp2, ...]}
        self.failure_counter = defaultdict(list)
        self.max_tracked_ips = 10000  # 防止記憶體無限增長

        # 封鎖佇列：防止並發 API 呼叫導致 HTTP 500
        self.ban_queue = asyncio.Queue()
        self.banning_ips = set()  # 正在佇列中或封鎖中的 IP
        self._worker_task = None
        self._cleanup_task = None

        # UDP Server
        self.transport = None
        self.protocol = None

    async def start_server(self, host: str = '0.0.0.0', port: int = 5141):
        """
        啟動 Syslog UDP Server

        Args:
            host: 監聽位址 (預設 0.0.0.0 = 所有介面)
            port: 監聽埠號 (預設 514 = Syslog 標準埠)
        """
        loop = asyncio.get_event_loop()

        print(f"\n[Syslog] Starting UDP server on {host}:{port}")

        # 建立 UDP endpoint
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(self.handle_syslog),
            local_addr=(host, port)
        )

        print(f"[Syslog] Server started successfully")
        print(f"[Syslog] Threshold: {self.threshold} failures in {self.time_window}s")
        print(f"[Syslog] Whitelist: {len(self.whitelist_ips) + len(self.whitelist_networks)} entries")

        # 啟動封鎖佇列 worker
        self._worker_task = asyncio.create_task(self._ban_worker())
        print(f"[Syslog] Ban queue worker started")

        # 啟動定期清理 task（每小時清理過期計數器）
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        print(f"[Syslog] Periodic cleanup task started")

    async def stop_server(self):
        """停止 Syslog Server"""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        if self.transport:
            self.transport.close()
            print("[Syslog] Server stopped")

    async def handle_syslog(self, message: str, addr: tuple):
        """
        處理 Syslog 訊息

        Args:
            message: Syslog 訊息內容
            addr: 來源位址 (ip, port)
        """
        # 解析 IP
        ip = self._parse_ip_from_syslog(message)

        if not ip:
            # 無法解析出 IP，可能不是登入失敗事件
            return

        # 檢查白名單（支援精確 IP 和 CIDR 網段）
        if self._is_whitelisted(ip):
            print(f"[Syslog] IP {ip} in whitelist, ignored")
            return

        # 記錄失敗時間
        now = datetime.now()
        self.failure_counter[ip].append(now)

        # 清理過期記錄（超過時間窗口）
        cutoff_time = now - timedelta(seconds=self.time_window)
        self.failure_counter[ip] = [
            ts for ts in self.failure_counter[ip]
            if ts > cutoff_time
        ]

        # 計算時間窗口內的失敗次數
        count = len(self.failure_counter[ip])

        print(f"[Syslog] IP {ip} failed login attempt: {count}/{self.threshold}")

        # 達到閾值，觸發自動封鎖
        if count >= self.threshold:
            await self._auto_ban(ip, count)

    def _is_whitelisted(self, ip: str) -> bool:
        """檢查 IP 是否在白名單中（支援精確 IP 和 CIDR 網段）"""
        if ip in self.whitelist_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in network for network in self.whitelist_networks)
        except ValueError:
            return False

    def _parse_ip_from_syslog(self, message: str) -> Optional[str]:
        """
        從 Syslog 訊息解析來源 IP

        FortiGate Syslog 格式範例：
        <134>date=2024-02-04 time=10:30:25 ... user="admin" src=192.168.1.100 ... msg="Administrator admin login failed from 192.168.1.100"

        Returns:
            IP 位址字串，如果無法解析則返回 None
        """
        # 嘗試多種解析模式
        patterns = [
            r'src=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',  # src=x.x.x.x
            r'srcip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',  # srcip=x.x.x.x
            r'login failed from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',  # from x.x.x.x
        ]

        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                ip = match.group(1)
                # 驗證 IP 格式
                if self._is_valid_ip(ip):
                    return ip

        return None

    def _is_valid_ip(self, ip: str) -> bool:
        """驗證 IP 格式（使用 ipaddress 模組）"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    async def _periodic_cleanup(self):
        """定期清理過期的失敗計數器（每小時執行一次）"""
        while True:
            try:
                await asyncio.sleep(3600)  # 每小時清理一次

                now = datetime.now()
                cutoff = now - timedelta(seconds=self.time_window)
                removed = 0

                # 清理每個 IP 的過期時間戳
                for ip in list(self.failure_counter.keys()):
                    self.failure_counter[ip] = [
                        ts for ts in self.failure_counter[ip]
                        if ts > cutoff
                    ]
                    if not self.failure_counter[ip]:
                        del self.failure_counter[ip]
                        removed += 1

                # 如果追蹤 IP 數超過上限，移除最舊的 10%
                if len(self.failure_counter) > self.max_tracked_ips:
                    sorted_ips = sorted(
                        self.failure_counter.items(),
                        key=lambda x: max(x[1]) if x[1] else datetime.min
                    )
                    remove_count = len(sorted_ips) // 10
                    for ip, _ in sorted_ips[:remove_count]:
                        del self.failure_counter[ip]
                        removed += 1

                print(f"[Cleanup] Removed {removed} stale IP records, tracking {len(self.failure_counter)} IPs")

            except asyncio.CancelledError:
                print("[Cleanup] Periodic cleanup stopped")
                break

    async def _auto_ban(self, ip: str, count: int):
        """
        將 IP 加入封鎖佇列（防止重複觸發）

        Args:
            ip: 要封鎖的 IP
            count: 失敗次數
        """
        # 如果 IP 已在佇列中或正在封鎖，忽略
        if ip in self.banning_ips:
            print(f"[AutoBan] IP {ip} already in ban queue, skipping")
            return

        # 立刻清空計數器，防止重複觸發
        if ip in self.failure_counter:
            del self.failure_counter[ip]

        # 加入佇列
        self.banning_ips.add(ip)
        await self.ban_queue.put((ip, count))
        print(f"\n[AutoBan] IP {ip} added to ban queue (failed {count} times), queue size: {self.ban_queue.qsize()}")

    async def _ban_worker(self):
        """
        封鎖佇列 Worker：依序處理封鎖請求，避免並發 API 呼叫
        """
        print("[BanWorker] Started")
        while True:
            try:
                ip, count = await self.ban_queue.get()

                print(f"\n[BanWorker] Processing ban for {ip} (failed {count} times)")

                try:
                    comment = f"Auto-banned: {count} failed attempts in {self.time_window}s at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    success = await self.fortigate.block_ip(ip, comment)

                    if success:
                        print(f"[BanWorker] Successfully banned {ip}")

                        if self.notifier:
                            await self.notifier(
                                ip=ip,
                                fail_count=count,
                                source_system="FortiGate Syslog",
                                event_type="login_failure"
                            )
                    else:
                        print(f"[BanWorker] Failed to ban {ip}")

                except Exception as e:
                    print(f"[BanWorker] Error banning {ip}: {e}")

                finally:
                    # 無論成功失敗，都從 banning_ips 移除
                    self.banning_ips.discard(ip)
                    self.ban_queue.task_done()

            except asyncio.CancelledError:
                print("[BanWorker] Stopped")
                break

    def get_stats(self) -> dict:
        """取得統計資料"""
        return {
            "monitored_ips": len(self.failure_counter),
            "failure_details": {
                ip: len(timestamps)
                for ip, timestamps in self.failure_counter.items()
            },
            "threshold": self.threshold,
            "time_window": self.time_window,
            "whitelist_count": len(self.whitelist_ips) + len(self.whitelist_networks),
            "ban_queue_size": self.ban_queue.qsize(),
            "banning_ips": list(self.banning_ips)
        }


async def test_syslog_processor():
    """測試 Syslog Processor（開發用）"""
    import os
    from dotenv import load_dotenv

    # 載入環境變數
    load_dotenv("../.env")

    print("=" * 60)
    print("  Syslog Processor Test")
    print("=" * 60)

    # 從環境變數決定使用哪個 FortiGate Client
    use_real_api = os.getenv("USE_REAL_FORTIGATE", "false").lower() == "true"

    if use_real_api:
        try:
            from fortigate_client import FortiGateClient
            print("\n[MODE] Using REAL FortiGate API for testing")
            print("[WARN] Test IPs WILL BE ACTUALLY BLOCKED!\n")
            fortigate = FortiGateClient()
        except ImportError:
            from telegram_bot import MockFortiGateClient
            print("\n[MODE] Using Mock Client (fallback)\n")
            fortigate = MockFortiGateClient()
    else:
        from telegram_bot import MockFortiGateClient
        print("\n[MODE] Using Mock Client (Safe)\n")
        fortigate = MockFortiGateClient()

    # 通知函數（模擬）
    async def mock_notifier(ip, fail_count, source_system, event_type):
        print(f"\n[Notification] IP {ip} banned!")
        print(f"  - Failures: {fail_count}")
        print(f"  - Source: {source_system}")
        print(f"  - Type: {event_type}")

    # 建立 Processor
    processor = SyslogProcessor(
        fortigate_client=fortigate,
        notifier=mock_notifier,
        threshold=3,
        time_window=600
    )

    # 測試解析功能
    print("\n[Test] Parsing Syslog messages...\n")

    test_messages = [
        '<134>date=2024-02-04 time=10:30:25 user="admin" src=192.168.1.100 msg="Administrator admin login failed from 192.168.1.100"',
        '<134>date=2024-02-04 time=10:30:26 srcip=192.168.1.100 msg="VPN login failed"',
        '<134>date=2024-02-04 time=10:30:27 msg="SSH login failed from 192.168.1.100"',
    ]

    for i, msg in enumerate(test_messages, 1):
        print(f"Message {i}:")
        await processor.handle_syslog(msg, ('127.0.0.1', 12345))
        await asyncio.sleep(0.1)

    # 顯示統計
    print("\n[Stats]")
    stats = processor.get_stats()
    print(f"  Monitored IPs: {stats['monitored_ips']}")
    print(f"  Details: {stats['failure_details']}")

    print("\n[Test] Completed")


async def run_server():
    """持續運行 Syslog Server（生產模式）"""
    import os
    from dotenv import load_dotenv

    # 載入環境變數
    load_dotenv("../.env")

    print("=" * 60)
    print("  Syslog Processor - Server Mode")
    print("=" * 60)

    # 從環境變數決定使用哪個 FortiGate Client
    use_real_api = os.getenv("USE_REAL_FORTIGATE", "false").lower() == "true"

    if use_real_api:
        # 使用真實 FortiGate API
        try:
            from fortigate_client import FortiGateClient
            print("\n[MODE] Using REAL FortiGate API")
            print("[WARN] *** IPs WILL BE ACTUALLY BLOCKED ON FORTIGATE ***")
            print("[WARN] *** Make sure this is what you want! ***\n")
            fortigate = FortiGateClient()
        except ImportError as e:
            print(f"\n[ERROR] Cannot import FortiGateClient: {e}")
            print("[ERROR] Falling back to Mock Client\n")
            from telegram_bot import MockFortiGateClient
            fortigate = MockFortiGateClient()
    else:
        # 使用 Mock Client（預設，安全模式）
        from telegram_bot import MockFortiGateClient
        print("\n[MODE] Using Mock FortiGate Client (Safe Mode)")
        print("[INFO] IPs will NOT be actually blocked")
        print("[INFO] Set USE_REAL_FORTIGATE=true in .env to use real API\n")
        fortigate = MockFortiGateClient()

    # 通知函數（模擬）
    async def mock_notifier(ip, fail_count, source_system, event_type):
        print(f"\n[Notification] IP {ip} banned!")
        print(f"  - Failures: {fail_count}")
        print(f"  - Source: {source_system}")
        print(f"  - Type: {event_type}\n")

    # 建立 Processor
    processor = SyslogProcessor(
        fortigate_client=fortigate,
        notifier=mock_notifier,
        threshold=3,
        time_window=600
    )

    # 啟動 Server (使用 5141 避免權限問題，正式環境改用 514)
    await processor.start_server(host='0.0.0.0', port=5141)

    print("\n[Server] Waiting for Syslog messages...")
    print("[Server] Press Ctrl+C to stop\n")

    # 保持運行
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        await processor.stop_server()


if __name__ == "__main__":
    import sys

    # 檢查命令列參數
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        # 測試模式
        print("\n[Mode] Test Mode\n")
        try:
            asyncio.run(test_syslog_processor())
        except KeyboardInterrupt:
            print("\n\n[STOP] Test stopped")
    else:
        # 持續運行模式
        print("\n[Mode] Server Mode")
        print("[Tip] Use 'python syslog_processor.py test' for test mode\n")
        try:
            asyncio.run(run_server())
        except KeyboardInterrupt:
            print("\n\n[STOP] Server stopped")

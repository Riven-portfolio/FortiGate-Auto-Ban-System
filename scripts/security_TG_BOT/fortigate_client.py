"""
FortiGate API Client
提供 FortiGate REST API 的 Python 接口
"""

import httpx
import os
from datetime import datetime
from typing import List, Optional, Dict
from dotenv import load_dotenv

# 載入環境變數（.env 在上一層 scripts/.env）
load_dotenv("../.env")

FORTIGATE_HOST = os.getenv("FORTIGATE_HOST")
FORTIGATE_TOKEN = os.getenv("FORTIGATE_TOKEN")
BASE_URL = f"https://{FORTIGATE_HOST}/api/v2/cmdb"


class FortiGateClient:
    """FortiGate REST API Client"""

    def __init__(self, host: str = None, token: str = None):
        """
        初始化 FortiGate Client

        Args:
            host: FortiGate 主機位址（預設從環境變數讀取）
            token: API Token（預設從環境變數讀取）
        """
        self.host = host or FORTIGATE_HOST
        self.token = token or FORTIGATE_TOKEN
        self.base_url = f"https://{self.host}/api/v2/cmdb"

        if not self.host or not self.token:
            raise ValueError("Missing FORTIGATE_HOST or FORTIGATE_TOKEN")

        # 建立 HTTP Client
        self.client = httpx.AsyncClient(
            verify=False,  # 忽略 SSL 憑證驗證（自簽憑證）
            timeout=30.0,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
        )

    async def close(self):
        """關閉 HTTP Client 連線"""
        await self.client.aclose()

    async def list_banned_ips(self) -> List[str]:
        """
        列出所有被封鎖的 IP

        Returns:
            List[str]: IP 列表
        """
        try:
            # 取得 ban_list Address Group 的所有 members
            response = await self.client.get(
                f"{self.base_url}/firewall/addrgrp/ban_list"
            )

            if response.status_code == 200:
                data = response.json()
                members = data.get("results", [{}])[0].get("member", [])

                # 處理 member 格式（可能是 dict 或 string）
                ip_list = []
                for member in members:
                    if isinstance(member, dict):
                        name = member.get("name", "")
                    else:
                        name = member

                    # 從 Address 名稱提取 IP（格式：ban_192_168_1_100）
                    if name.startswith("ban_"):
                        ip = name[4:].replace("_", ".")
                        ip_list.append(ip)

                return ip_list

            elif response.status_code == 404:
                print("[WARN] ban_list Group 不存在")
                return []

            else:
                print(f"[ERROR] 取得 ban_list 失敗: HTTP {response.status_code}")
                return []

        except Exception as e:
            print(f"[ERROR] list_banned_ips 失敗: {str(e)}")
            return []

    async def get_ip_info(self, ip: str) -> Optional[Dict]:
        """
        取得 IP 的詳細資訊

        Args:
            ip: 要查詢的 IP 位址

        Returns:
            Optional[Dict]: IP 資訊（comment, subnet 等），如果不存在則返回 None
        """
        try:
            address_name = f"ban_{ip.replace('.', '_')}"

            response = await self.client.get(
                f"{self.base_url}/firewall/address/{address_name}"
            )

            if response.status_code == 200:
                data = response.json()
                result = data.get("results", [{}])[0]

                return {
                    "ip": ip,
                    "name": result.get("name"),
                    "subnet": result.get("subnet"),
                    "comment": result.get("comment", ""),
                    "type": result.get("type")
                }

            elif response.status_code == 404:
                return None

            else:
                print(f"[ERROR] 取得 IP 資訊失敗: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"[ERROR] get_ip_info 失敗: {str(e)}")
            return None

    async def block_ip(self, ip: str, comment: str) -> bool:
        """
        封鎖 IP（建立 Address 並加入 ban_list）

        Args:
            ip: 要封鎖的 IP 位址
            comment: 封鎖原因註解

        Returns:
            bool: 成功返回 True，失敗返回 False
        """
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[ERROR] block_ip: 無效的 IP 格式: {ip}")
            return False

        try:
            address_name = f"ban_{ip.replace('.', '_')}"

            # Step 1: 建立 Address
            address_payload = {
                "name": address_name,
                "subnet": f"{ip}/32",
                "type": "ipmask",
                "comment": comment
            }

            response = await self.client.post(
                f"{self.base_url}/firewall/address",
                json=address_payload
            )

            # 如果 Address 已存在（HTTP 400）也視為成功
            if response.status_code not in [200, 201, 400]:
                print(f"[ERROR] 建立 Address 失敗: HTTP {response.status_code}")
                print(f"[ERROR] Response: {response.text[:200]}")
                return False

            # Step 2: 加入到 ban_list Group
            # 先取得目前的 members
            response = await self.client.get(
                f"{self.base_url}/firewall/addrgrp/ban_list"
            )

            if response.status_code != 200:
                print(f"[ERROR] 無法讀取 ban_list: HTTP {response.status_code}")
                return False

            data = response.json()
            current_members = data.get("results", [{}])[0].get("member", [])

            # 處理 member 格式
            member_names = []
            for m in current_members:
                if isinstance(m, dict):
                    member_names.append(m.get("name"))
                else:
                    member_names.append(m)

            # 檢查是否已在 Group 中
            if address_name in member_names:
                print(f"[INFO] IP {ip} 已在 ban_list 中")
                return True

            # 加入新的 Address
            member_names.append(address_name)

            update_payload = {
                "member": [{"name": name} for name in member_names]
            }

            response = await self.client.put(
                f"{self.base_url}/firewall/addrgrp/ban_list",
                json=update_payload
            )

            if response.status_code == 200:
                print(f"[OK] IP {ip} 已成功加入 ban_list")
                return True
            else:
                print(f"[ERROR] 加入 ban_list 失敗: HTTP {response.status_code}")
                return False

        except Exception as e:
            print(f"[ERROR] block_ip 失敗: {str(e)}")
            return False

    async def unblock_ip(self, ip: str) -> bool:
        """
        解除封鎖 IP（從 ban_list 移除並刪除 Address）

        Args:
            ip: 要解除封鎖的 IP 位址

        Returns:
            bool: 成功返回 True，失敗返回 False
        """
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[ERROR] unblock_ip: 無效的 IP 格式: {ip}")
            return False

        try:
            address_name = f"ban_{ip.replace('.', '_')}"

            # Step 1: 從 ban_list Group 移除
            response = await self.client.get(
                f"{self.base_url}/firewall/addrgrp/ban_list"
            )

            if response.status_code != 200:
                print(f"[ERROR] 無法讀取 ban_list: HTTP {response.status_code}")
                return False

            data = response.json()
            current_members = data.get("results", [{}])[0].get("member", [])

            # 處理 member 格式
            member_names = []
            for m in current_members:
                if isinstance(m, dict):
                    member_names.append(m.get("name"))
                else:
                    member_names.append(m)

            # 檢查 Address 是否在 Group 中
            if address_name not in member_names:
                print(f"[WARN] IP {ip} 不在 ban_list 中")
                # 仍然嘗試刪除 Address（可能孤立存在）
            else:
                # 從 Group 移除
                member_names.remove(address_name)

                update_payload = {
                    "member": [{"name": name} for name in member_names]
                }

                response = await self.client.put(
                    f"{self.base_url}/firewall/addrgrp/ban_list",
                    json=update_payload
                )

                if response.status_code != 200:
                    print(f"[ERROR] 從 ban_list 移除失敗: HTTP {response.status_code}")
                    return False

            # Step 2: 刪除 Address
            response = await self.client.delete(
                f"{self.base_url}/firewall/address/{address_name}"
            )

            if response.status_code == 200:
                print(f"[OK] IP {ip} 已成功解除封鎖")
                return True
            elif response.status_code == 404:
                print(f"[WARN] Address {address_name} 不存在")
                return True  # 視為成功（已經不存在了）
            else:
                print(f"[ERROR] 刪除 Address 失敗: HTTP {response.status_code}")
                return False

        except Exception as e:
            print(f"[ERROR] unblock_ip 失敗: {str(e)}")
            return False

    async def is_ip_blocked(self, ip: str) -> bool:
        """
        檢查 IP 是否已被封鎖

        Args:
            ip: 要檢查的 IP 位址

        Returns:
            bool: 已封鎖返回 True，否則返回 False
        """
        banned_ips = await self.list_banned_ips()
        return ip in banned_ips


# 測試用
async def test_client():
    """測試 FortiGate Client 功能"""
    print("=" * 60)
    print("FortiGate API Client 測試")
    print("=" * 60)

    client = FortiGateClient()

    try:
        # 測試 1: 列出已封鎖的 IP
        print("\n[Test 1] 列出已封鎖的 IP")
        banned_ips = await client.list_banned_ips()
        print(f"已封鎖的 IP: {banned_ips}")

        # 測試 2: 查詢 IP 資訊
        if banned_ips:
            test_ip = banned_ips[0]
            print(f"\n[Test 2] 查詢 IP 資訊: {test_ip}")
            info = await client.get_ip_info(test_ip)
            print(f"IP 資訊: {info}")

        # 測試 3: 封鎖測試 IP
        test_ban_ip = "192.0.2.100"  # TEST-NET-1 (RFC 5737)
        print(f"\n[Test 3] 封鎖測試 IP: {test_ban_ip}")
        success = await client.block_ip(test_ban_ip, "Test ban from Python client")
        print(f"封鎖結果: {'成功' if success else '失敗'}")

        # 測試 4: 檢查是否已封鎖
        print(f"\n[Test 4] 檢查 {test_ban_ip} 是否已封鎖")
        is_blocked = await client.is_ip_blocked(test_ban_ip)
        print(f"封鎖狀態: {'已封鎖' if is_blocked else '未封鎖'}")

        # 測試 5: 解除封鎖
        print(f"\n[Test 5] 解除封鎖: {test_ban_ip}")
        success = await client.unblock_ip(test_ban_ip)
        print(f"解除封鎖結果: {'成功' if success else '失敗'}")

        # 驗證
        print(f"\n[Verify] 驗證 {test_ban_ip} 是否已解除")
        is_blocked = await client.is_ip_blocked(test_ban_ip)
        print(f"封鎖狀態: {'已封鎖' if is_blocked else '未封鎖'}")

        print("\n" + "=" * 60)
        print("[SUCCESS] 所有測試完成")
        print("=" * 60)

    finally:
        await client.close()


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_client())

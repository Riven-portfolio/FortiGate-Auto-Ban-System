# FortiGate Auto-Ban System - 部署指南

本文件說明如何使用 Docker 部署 FortiGate Auto-Ban System。

---

## 📋 部署前準備

### 1. 環境需求

- Docker Engine 20.10+
- Docker Compose 1.29+
- 至少 512MB 可用記憶體
- UDP Port 5141 可用

### 2. 環境變數設定

**重要安全性設計**：
- `.env` 檔案**不會**被打包進 Docker image（避免敏感資訊洩漏）
- 環境變數在 runtime 透過 volume 掛載或 env_file 提供
- 每次啟動容器都從本機的 `scripts/.env` 讀取最新配置

複製環境變數範本：

```bash
cp scripts/.env.example scripts/.env
```

編輯 `scripts/.env` 填入實際參數：

```bash
# FortiGate 設定
FORTIGATE_HOST=your.fortigate.ip
FORTIGATE_TOKEN=your_api_token_here
FORTIGATE_VERIFY_SSL=false

# Telegram Bot 設定
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# 系統設定
USE_REAL_FORTIGATE=true              # 生產環境設為 true
SYSLOG_HOST=0.0.0.0                  # 監聽所有介面
SYSLOG_PORT=5141                     # Syslog UDP 端口
FAIL_THRESHOLD=5                     # 失敗次數閾值
TIME_WINDOW_SECONDS=600              # 時間窗口（秒）
```

**注意事項**：
- 修改 `.env` 後只需重啟容器（`docker-compose restart`），無需重新建立 image
- 確保 `.env` 檔案權限正確（建議 `chmod 600 scripts/.env`）

---

## 🚀 快速部署

### 方式 1: Docker Compose (推薦)

```bash
# 1. 建立並啟動容器
docker-compose up -d

# 2. 查看日誌
docker-compose logs -f

# 3. 停止服務
docker-compose down

# 4. 重新啟動
docker-compose restart
```

### 方式 2: Docker CLI

```bash
# 1. 建立映像檔
docker build -t fortigate-autoban:latest .

# 2. 執行容器
docker run -d \
  --name fortigate-autoban \
  --restart unless-stopped \
  -p 5141:5141/udp \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/scripts/.env:/app/.env:ro \
  --env-file scripts/.env \
  fortigate-autoban:latest

# 3. 查看日誌
docker logs -f fortigate-autoban

# 4. 停止容器
docker stop fortigate-autoban

# 5. 刪除容器
docker rm fortigate-autoban
```

---

## 🔧 進階配置

### 資源限制

編輯 `docker-compose.yml` 的 `deploy.resources` 區段：

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'      # 最多使用 2 個 CPU
      memory: 1G       # 最多使用 1GB 記憶體
    reservations:
      cpus: '1.0'      # 保證 1 個 CPU
      memory: 512M     # 保證 512MB 記憶體
```

### 日誌管理

Docker Compose 預設限制日誌大小：
- 單一檔案最大 10MB
- 最多保留 3 個檔案

應用程式日誌存放在 `./logs/` 目錄（volume 掛載），需要手動管理：

```bash
# 查看日誌大小
du -sh logs/

# 清理舊日誌（保留最近 7 天）
find logs/ -name "*.log" -mtime +7 -delete
```

### 網路設定

#### 本地測試環境
- 使用 `127.0.0.1:5141` 接收 Syslog
- 使用 `test_syslog_sender.py` 發送測試訊息

#### 生產環境（接收真實 FortiGate Syslog）
1. 設定 FortiGate Syslog Server 為容器 IP
2. 確保防火牆允許 UDP 5141
3. 設定 `SYSLOG_HOST=0.0.0.0`（監聽所有介面）

**FortiGate Syslog 設定範例：**
```
config log syslogd setting
    set status enable
    set server "<docker_host_ip>"
    set port 5141
    set facility user
    set source-ip ""
    set format default
end
```

---

## 🧪 測試與驗證

### 1. 健康檢查

```bash
# 查看容器狀態
docker-compose ps

# 應顯示 healthy 狀態
# NAME                  STATUS
# fortigate-autoban     Up 5 minutes (healthy)
```

### 2. 測試 Syslog 接收

從本機發送測試 Syslog：

```bash
# Windows (PowerShell)
cd scripts\security_TG_BOT
.venv\Scripts\python test_syslog_sender.py

# Linux
cd scripts/security_TG_BOT
.venv/bin/python test_syslog_sender.py
```

### 3. 查看系統運作

```bash
# 即時查看日誌
docker-compose logs -f

# 應該看到：
# [OK] FortiGate Client initialized
# [OK] Telegram Bot initialized
# [OK] Syslog Processor started on 0.0.0.0:5141
```

### 4. 測試 Telegram 通知

```bash
# 進入容器執行測試
docker exec -it fortigate-autoban python -c "
from telegram_bot import SecurityBot
import asyncio
bot = SecurityBot('YOUR_BOT_TOKEN', 'YOUR_CHAT_ID', None)
asyncio.run(bot.app.bot.send_message(chat_id='YOUR_CHAT_ID', text='[TEST] Docker deployment test'))
"
```

---

## 🐛 故障排除

### 問題 1: 容器啟動失敗

**檢查點：**
```bash
# 查看容器日誌
docker-compose logs

# 常見原因：
# - .env 檔案不存在或格式錯誤
# - Port 5141 被佔用
# - 環境變數缺少必要參數
```

**解決方案：**
```bash
# 檢查 .env 檔案
cat scripts/.env

# 檢查 Port 佔用 (Windows)
netstat -ano | findstr :5141

# 檢查 Port 佔用 (Linux)
netstat -tuln | grep 5141
```

### 問題 2: Syslog 無法接收

**檢查點：**
```bash
# 1. 確認容器正在監聽
docker exec fortigate-autoban netstat -uln | grep 5141

# 2. 檢查防火牆規則 (Linux)
sudo ufw status
sudo ufw allow 5141/udp

# 3. 檢查防火牆規則 (Windows)
# 控制台 → Windows Defender 防火牆 → 進階設定
# 新增輸入規則：UDP Port 5141
```

### 問題 3: Telegram 通知未發送

**檢查點：**
```bash
# 1. 確認環境變數正確
docker exec fortigate-autoban env | grep TELEGRAM

# 2. 測試 Bot Token
docker exec fortigate-autoban python -c "
import os
from telegram import Bot
import asyncio
token = os.getenv('TELEGRAM_BOT_TOKEN')
bot = Bot(token)
print(asyncio.run(bot.get_me()))
"

# 3. 查看應用程式日誌
docker-compose logs | grep "Notification"
```

### 問題 4: 容器記憶體不足

**症狀：** 容器自動重啟或被 OOM Killer 終止

**解決方案：**
```bash
# 增加記憶體限制
# 編輯 docker-compose.yml
deploy:
  resources:
    limits:
      memory: 1G  # 提高至 1GB

# 重新部署
docker-compose down
docker-compose up -d
```

---

## 🔄 更新與維護

### 更新應用程式

```bash
# 1. 停止容器
docker-compose down

# 2. 拉取最新代碼
git pull

# 3. 重新建立映像檔
docker-compose build

# 4. 啟動新容器
docker-compose up -d
```

### 備份與還原

```bash
# 備份環境變數與日誌
tar -czf backup-$(date +%Y%m%d).tar.gz scripts/.env logs/

# 還原
tar -xzf backup-20260207.tar.gz
```

### 定期維護

建議定期執行：
1. 清理舊日誌檔案（每週）
2. 檢查容器資源使用（每週）
3. 更新 Python 依賴套件（每月）
4. 更新 Docker 基礎映像檔（每季）

```bash
# 檢查容器資源使用
docker stats fortigate-autoban

# 清理 Docker 系統
docker system prune -a --volumes
```

---

## 📊 監控建議

### 基本監控

```bash
# 1. 容器狀態監控
watch -n 5 'docker-compose ps'

# 2. 資源使用監控
watch -n 5 'docker stats fortigate-autoban --no-stream'

# 3. 日誌即時監控
docker-compose logs -f --tail=100
```

### 進階監控（可選）

- **Prometheus + Grafana**: 收集容器 metrics
- **ELK Stack**: 集中式日誌管理
- **Uptime Kuma**: 服務健康度監控

---

## 🔒 安全性建議

1. **環境變數保護**
   - ✅ `.env` 不會被打包進 Docker image（已實作）
   - 不要將 `.env` 提交到 Git（已加入 .gitignore）
   - 使用 Docker Secrets（Swarm 模式，進階功能）
   - 限制 `.env` 檔案權限：`chmod 600 scripts/.env`

2. **網路隔離**
   - 只開放必要的 Port（5141/udp）
   - 使用防火牆限制來源 IP

3. **映像檔安全**
   - 定期更新基礎映像檔
   - 掃描映像檔漏洞（`docker scan`）

4. **日誌安全**
   - 避免記錄敏感資訊（API Token、密碼）
   - 設定適當的日誌輪替

---

## 📚 參考資源

- [Docker 官方文件](https://docs.docker.com/)
- [Docker Compose 文件](https://docs.docker.com/compose/)
- [專案 GitHub](./README.md)
- [系統架構文件](../SDD.md)
- [版本變更記錄](./version-history.md)

---

**建立日期**: 2026-02-07
**最後更新**: 2026-02-07

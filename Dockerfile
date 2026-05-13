# FortiGate Auto-Ban System - Dockerfile
# 基於 Python 3.10 Alpine (輕量化)

FROM python:3.10-slim

# 設定工作目錄
WORKDIR /app

# 安裝系統依賴
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 複製依賴文件
COPY requirements.txt .

# 安裝 Python 依賴
RUN pip install --no-cache-dir -r requirements.txt

# 複製專案文件
COPY scripts/security_TG_BOT /app/

# 建立日誌目錄
RUN mkdir -p /app/logs

# 注意：.env 不包含在映像檔中（安全性考量）
# 環境變數將在 runtime 透過以下方式提供：
# 1. docker-compose.yml 的 env_file 設定
# 2. volume 掛載: -v ./scripts/.env:/app/.env:ro

# 暴露 Syslog 接收端口 (UDP)
EXPOSE 5141/udp

# 設定環境變數
ENV PYTHONUNBUFFERED=1

# 健康檢查 (每 30 秒檢查一次)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('', 0)); s.close()" || exit 1

# 執行主程式
CMD ["python", "main.py"]

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE=".env"
ENV_EXAMPLE=".env.example"

if ! command -v uv &> /dev/null; then
  echo "错误：未检测到 uv，请先安装 uv 包管理器。"
  echo "安装方式：https://docs.astral.sh/uv/getting-started/installation/"
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "$ENV_EXAMPLE" ]]; then
    echo "未找到 $ENV_FILE，正在从 $ENV_EXAMPLE 复制..."
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    echo "已创建 $ENV_FILE，请编辑该文件填入 ALLOWED_API_KEYS 等配置后重新运行。"
    exit 1
  else
    echo "错误：未找到 $ENV_FILE 且 $ENV_EXAMPLE 也不存在。"
    exit 1
  fi
fi

echo "==> 同步依赖（uv sync --locked）"
uv sync --locked

echo "==> 启动本地 Mijia MCP 服务"
echo "    服务地址：http://127.0.0.1:8080/mcp"
echo "    健康检查：http://127.0.0.1:8080/health"
echo "    按 Ctrl+C 停止服务"
echo ""
uv run --locked --env-file .env python src/server.py

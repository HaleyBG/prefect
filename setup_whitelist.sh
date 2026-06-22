#!/usr/bin/env bash
# setup_whitelist.sh — 在新环境中部署 Prefect 出站白名单拦截
#
# 用法:
#   chmod +x setup_whitelist.sh
#   ./setup_whitelist.sh                    # 安装到当前 venv
#   ./setup_whitelist.sh /path/to/venv      # 安装到指定 venv
#   ./setup_whitelist.sh --remove           # 卸载
#
# 依赖: whitelist_proxy.py 必须与此脚本在同一目录。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXY_FILE="${SCRIPT_DIR}/whitelist_proxy.py"
ACTION="${1:-install}"

# 解析 venv 路径
if [[ "$ACTION" == "--remove" ]] || [[ "$ACTION" == "-r" ]]; then
    MODE="remove"
    VENV_PATH="${2:-${VIRTUAL_ENV:-.venv}}"
else
    MODE="install"
    VENV_PATH="${ACTION}"
    if [[ "$VENV_PATH" == "--remove" ]] || [[ "$VENV_PATH" == "-r" ]]; then
        MODE="remove"
        VENV_PATH="${2:-${VIRTUAL_ENV:-.venv}}"
    fi
fi

# 查找或指定 site-packages
SITE_PACKAGES=$(python3 -c "import sysconfig; print(sysconfig.get_path('purelib'))" 2>/dev/null || true)
if [[ -z "$SITE_PACKAGES" ]]; then
    if [[ -d "${VENV_PATH}" ]]; then
        SITE_PACKAGES=$(find "${VENV_PATH}" -type d -name "site-packages" 2>/dev/null | head -1)
    fi
fi

if [[ -z "$SITE_PACKAGES" ]] || [[ ! -d "$SITE_PACKAGES" ]]; then
    echo "ERROR: 无法找到 site-packages 目录"
    echo "请确认已在 venv 中，或手动指定: ./setup_whitelist.sh /path/to/.venv"
    exit 1
fi

PTH_FILE="${SITE_PACKAGES}/whitelist_proxy.pth"
DEST_FILE="${SITE_PACKAGES}/whitelist_proxy.py"

if [[ "$MODE" == "remove" ]]; then
    echo "=== 卸载 Prefect 出站白名单 ==="
    rm -f "$PTH_FILE" "$DEST_FILE"
    echo "[OK] 已删除: $PTH_FILE"
    echo "[OK] 已删除: $DEST_FILE"
    echo "拦截已关闭。"
    exit 0
fi

if [[ ! -f "$PROXY_FILE" ]]; then
    echo "ERROR: 找不到 whitelist_proxy.py，请将其放在与此脚本相同的目录"
    exit 1
fi

echo "=== 安装 Prefect 出站白名单 ==="
echo "site-packages: $SITE_PACKAGES"

# 1. 复制 whitelist_proxy.py 到 site-packages（使其可导入）
cp "$PROXY_FILE" "$DEST_FILE"
echo "[OK] 已复制: $PROXY_FILE → $DEST_FILE"

# 2. 创建 .pth 文件，Python 启动时自动 import
echo "import whitelist_proxy" > "$PTH_FILE"
echo "[OK] 已创建: $PTH_FILE"

# 3. 验证
echo ""
echo "=== 验证 ==="
if python3 -c "import whitelist_proxy; print('拦截模块加载成功')" 2>&1; then
    echo ""
    echo "=== 安装完成 ==="
    echo ""
    echo "现在可以直接启动 Prefect，拦截自动生效:"
    echo ""
    echo "  prefect server start"
    echo "  python my_flow.py"
    echo ""
    echo "建议同时设置环境变量（双重保险）:"
    echo "  export DO_NOT_TRACK=1"
    echo "  export PREFECT_SERVER_ANALYTICS_ENABLED=false"
    echo ""
    echo "卸载: ./setup_whitelist.sh --remove"
else
    echo "[FAIL] 验证失败，请检查 Python 环境"
    exit 1
fi

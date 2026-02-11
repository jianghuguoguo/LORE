#!/bin/bash

echo "================================================================================"
echo "                   爬虫管理系统 Web 界面启动脚本"
echo "================================================================================"
echo ""

echo "[1/3] 检查Python环境..."
if ! command -v python3 &> /dev/null; then
    echo "❌ 未检测到Python3，请先安装Python 3.8+"
    exit 1
fi
python3 --version
echo ""

echo "[2/3] 检查依赖包..."
if ! python3 -c "import flask" &> /dev/null; then
    echo "⚠️  Flask未安装，正在安装依赖..."
    pip3 install Flask flask-cors
    echo ""
fi

echo "[3/3] 启动Web服务..."
echo ""
echo "================================================================================"
echo "🚀 服务即将启动"
echo "================================================================================"
echo "访问地址: http://localhost:5000"
echo "按 Ctrl+C 停止服务"
echo "================================================================================"
echo ""

cd "$(dirname "$0")"
python3 app.py

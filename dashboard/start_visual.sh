#!/bin/bash

echo "================================================================================"
echo "   Evo-Pentest 智能检索可视化系统"
echo "   System 2 Reflection - Adaptive Retrieval"
echo "================================================================================"
echo ""
echo "[1/2] 启动 Flask 服务器..."

cd "$(dirname "$0")"
python3 app.py

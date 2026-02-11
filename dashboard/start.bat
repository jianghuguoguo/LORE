@echo off
chcp 65001 >nul
echo ================================================================================
echo                    爬虫管理系统 Web 界面启动脚本
echo ================================================================================
echo.

echo [1/3] 检查Python环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 未检测到Python，请先安装Python 3.8+
    pause
    exit /b 1
)
python --version
echo.

echo [2/3] 检查依赖包...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Flask未安装，正在安装依赖...
    pip install Flask flask-cors
    echo.
)

echo [3/3] 启动Web服务...
echo.
echo ================================================================================
echo 🚀 服务即将启动
echo ================================================================================
echo 访问地址: http://localhost:5000
echo 按 Ctrl+C 停止服务
echo ================================================================================
echo.

cd /d "%~dp0"
python app.py

pause

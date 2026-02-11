# 🚀 快速启动指南

## 1️⃣ 安装依赖（首次运行）

```bash
pip install Flask flask-cors
```

或者安装所有依赖：

```bash
pip install -r requirements.txt
```

## 2️⃣ 启动Web界面

### Windows用户

**方法1：双击启动脚本**
- 双击 `start.bat` 文件

**方法2：命令行启动**
```bash
cd dashboard
python app.py
```

### Linux/Mac用户

**方法1：使用启动脚本**
```bash
cd dashboard
chmod +x start.sh
./start.sh
```

**方法2：直接启动**
```bash
cd dashboard
python3 app.py
```

## 3️⃣ 访问界面

打开浏览器访问：**http://localhost:5000**

## 4️⃣ 使用步骤

1. ✅ 选择要使用的爬虫数据源
2. ✍️ 输入搜索关键词（如：渗透测试、CVE-2024）
3. 🔢 设置最大爬取页数
4. ▶️ 点击"开始爬取"
5. 📊 查看实时进度和日志
6. 💾 爬取完成后查看结果

## 🎯 快捷操作

- **全选数据源**: 点击"全选"按钮
- **清空日志**: 点击"清空日志"按钮
- **刷新状态**: 点击"刷新状态"按钮
- **停止爬取**: 点击"停止爬取"按钮

## 📋 可用的爬虫

- ✅ **CSDN**: 技术博客文章
- ✅ **GitHub**: 代码仓库和讨论
- ✅ **MITRE ATT&CK**: 攻击技术知识库
- ✅ **奇安信**: 安全社区文章
- ✅ **先知**: 安全技术社区

## ⚡ 常见问题

### Q: 端口5000被占用？

修改 `dashboard/app.py` 中的端口号：
```python
app.run(host='0.0.0.0', port=8080)  # 改为8080或其他端口
```

### Q: 爬虫无法启动？

1. 检查 `crawlers/config.py` 中的配置
2. 确保CSDN Cookie已配置（对于CSDN爬虫）
3. 查看实时日志获取详细错误信息

### Q: 如何停止服务？

按键盘 `Ctrl + C` 即可停止服务

## 📞 获取帮助

查看完整文档：`dashboard/README.md`

---

**Happy Crawling! 🎉**

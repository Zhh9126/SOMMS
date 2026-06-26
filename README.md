#  安全运维管理系统

一款轻量级的开源安全运维管理平台，集资产纳管、漏洞跟踪、资产测绘、配置核查、远程终端、批量运维于一体，帮助安全团队在一个平台上完成安全运维的完整闭环。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0%2B-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Nuclei](https://img.shields.io/badge/Nuclei-3.0%2B-orange.svg)](https://github.com/projectdiscovery/nuclei)

---

## 📌 项目简介

在安全运维工作中，我们常常需要在多个工具之间反复切换：用 Excel 管理资产，用漏洞平台跟踪漏洞，用 Nmap 做资产测绘，用 Xshell 远程运维……信息割裂、效率低下。

**** 将分散的安全运维能力整合到一个统一的 Web 平台中，实现“资产发现 → 资产管理 → 漏洞检测 → 配置核查 → 远程运维 → 批量任务”的全流程闭环。它轻量、易用、可扩展，专为中小型企业和安全从业者设计。

---

## ✨ 核心功能

| 功能模块 | 主要能力 |
|---------|----------|
| **资产管理** | 资产增删改查、批量导入导出、状态标记、标签分类、账号凭证管理 |
| **漏洞全生命周期管理** | 漏洞录入、修复标记、复测验证、风险统计看板 |
| **资产测绘** | 主机存活探测 & 端口扫描、子域爆破（300+ 字典）、目录探测、Web 指纹识别 |
| **等保配置核查** | Linux/Windows 安全配置项自动化检查、结果报告导出 |
| **Nuclei 漏洞扫描** | 集成 Nuclei 引擎，支持自定义模板、结果自动入库 |
| **弱口令检测** | SSH/MySQL/FTP/Telnet/RDP/POP3 多协议弱口令爆破 |
| **远程终端** | 基于 xterm.js 的交互式 SSH 终端，接近 Xshell 体验 |
| **批量运维** | 批量命令执行、批量文件分发、定时任务调度 |
| **审计日志** | 全操作审计、按日期归档、可追溯 |

---

## 🚀 快速开始

### 环境要求
- Python 3.8 或更高版本
- pip 包管理器
- （可选）Nuclei 引擎用于漏洞扫描

### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/Zhh9126/SOMMS.git
cd SOMMS

# 2. 安装依赖
pip install -r requirements.txt

# 3. 启动服务
python app.py
```

### 首次访问

- 浏览器访问 `http://localhost:5000`
- 默认管理员账号：`admin` / `123456`
- 登录后请立即修改密码

---

## 🖥️ 技术栈

| 组件 | 技术 |
|------|------|
| Web 框架 | Flask |
| 数据库 | SQLite (Peewee ORM) |
| 前端框架 | Bootstrap 5 + jQuery |
| 终端模拟 | xterm.js |
| 实时通信 | WebSocket (websockets) |
| SSH 连接 | Paramiko |
| 漏洞扫描 | Nuclei (可选集成) |
| 异步任务 | threading + asyncio |

---

## 📁 项目结构

```
sskit/
├── app.py                # Flask 主应用
├── models.py             # 数据模型
├── tasks.py              # 异步任务（扫描、核查、爆破等）
├── utils.py              # 工具函数
├── config.py             # 配置文件
├── requirements.txt      # 依赖列表
├── templates/            # HTML 模板
├── static/               # 静态资源
├── audit_logs/           # 审计日志存储
├── scan_reports/         # 扫描报告存储
└── nuclei_templates/     # Nuclei 模板（可选）
```

---

## 🧩 运行截图

> 截图占位，可后续补充

- 仪表盘概览
- 资产管理列表
- 漏洞跟踪看板
- 远程终端界面
- 批量运维结果

---

## 🤝 贡献指南

欢迎通过 Issue 和 Pull Request 参与贡献。在提交 PR 前，请确保：

1. 代码风格符合 PEP 8 规范
2. 新功能已添加相应说明
3. 不影响现有功能

---

## 📄 许可证

本项目采用 [MIT 许可证](LICENSE)，可自由使用、修改、分发。

---

## 🙏 致谢

- [Nuclei](https://github.com/projectdiscovery/nuclei) – 强大的漏洞扫描引擎
- [xterm.js](https://xtermjs.org/) – 终端模拟组件
- [Paramiko](https://www.paramiko.org/) – SSH 客户端库

---

## 📞 联系方式

- 项目主页：https://github.com/Zhh9126/SOMMS
- 问题反馈：https://github.com/Zhh9126/SOMMS/issues

---

**让安全运维，简单一点。**

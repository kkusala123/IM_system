
# 📡 即时通讯系统

一个基于 Flask + Bootstrap5 的简易即时通讯系统，包含注册、登录、用户管理、聊天室 UI Mockup 和动态主页效果，支持 SQLite 本地数据库。

---

## 📸 项目预览

![截图示例](static/img/example.jpg)

- 🌐 动态主界面，带背景图和缓动动画  
- 👤 用户注册 / 登录 / 注销  
- 💬 简易聊天室界面  
- 📊 在线人数显示  

---

## 📂 项目结构

```
project/
├── app.py                   # 主程序
├── instance/
│   └── users.db             # SQLite 数据库文件（首次运行自动生成）
├── static/
│   ├── css/
│   │   └── style.css        # 自定义样式
│   └── img/
│       └── bg.jpg           # 背景图片
├── templates/
│   ├── base.html            # 基础页面模板
│   ├── home.html            # 首页
│   ├── register.html        # 注册页
│   ├── login.html           # 登录页
│   ├── dashboard.html       # 用户仪表盘
│   └── chatroom.html        # 聊天室界面
├── requirements.txt         # 依赖库文件
└── README.md                # 项目说明文件
```

---

## 🛠️ 安装方法

1️⃣ 克隆项目：

```bash
https://github.com/kkusala123/python-project_deepseek.git
cd python-project_deepseek
```

2️⃣ 安装依赖：

```bash
pip install -r requirements.txt
```

3️⃣ 运行程序：

```bash
python app.py
```

访问：http://127.0.0.1:5000/

---

## 📦 依赖库

- Flask  
- Flask-SQLAlchemy  
- Werkzeug  
- Bootstrap 5 (CDN)  

安装：

```bash
pip install flask flask_sqlalchemy werkzeug
```

---

## 📌 功能介绍

- 用户注册、登录、退出登录
- 密码加密存储
- 在线人数实时展示（模拟）
- 聊天室界面 UI Mockup（后续可扩展 WebSocket 聊天）
- 背景图片、主页动态效果、按钮悬停动画

---

## 📈 后续计划

- Socket.IO 实现实时聊天功能  
- 聊天记录保存至数据库  
- 私聊 / 群聊模式  
- 在线用户列表实时更新  

---

## 📑 License

MIT License. 自由开源，欢迎学习、拓展与引用。

---

## ✨ 作者

kkusala123 | 2025

如果觉得有用，欢迎 Star ⭐️！

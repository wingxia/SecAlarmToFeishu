# SecAlarmToFeishu（EDR 告警 → 飞书）

一个基于 Python 的小脚本：自动登录 EDR 管理平台，定时拉取“设备告警/overview”接口数据，发现新告警后按既定卡片样式推送到飞书群机器人。

## 功能
- 自动模拟浏览器登录（含 RSA 密码加密流程）
- 自动获取/维护 Cookie、token，调用 EDR overview API
- 验证码：使用 Tesseract OCR 识别；识别结果不是 4 位则自动刷新重试
- 登录失效自动重新登录
- 告警去重（按 `event_id` 记录已发送）
- 飞书推送：支持交互卡片（告警详情）+ 文本消息（状态提示/报错）

## 目录结构（示例）
- `main.py`：主入口，循环轮询 API（默认 2 分钟）
- `edr_client.py`：登录、验证码处理、API 调用封装
- `feishu.py`（如果你拆分了）：飞书签名与发送（卡片/文本）
- `sent_event_ids.txt`：已推送的 `event_id` 去重记录（自动生成）
- `captcha/`：验证码临时图片目录（登录成功后会清理）

## 依赖
- Python 3.10+（建议使用 venv）
- macOS 可用 Homebrew 安装 Tesseract：
  - `brew install tesseract`
- Python 包：
  - `requests`
  - `pycryptodome`
  - `pillow`
  - `pytesseract`

安装示例：
```bash
python -m venv .venv
source .venv/bin/activate
pip install requests pycryptodome pillow pytesseract
brew install tesseract
```

## 配置
在代码里或通过环境变量配置以下内容（推荐用环境变量/配置文件，别硬编码到仓库）：
- EDR：
  - `BASE_URL`（默认 `https://edr.chinawayltd.com`）
  - `USERNAME` / `PASSWORD`
- 飞书机器人：
  - `FEISHU_WEBHOOK`
  - `FEISHU_SECRET`

## 运行
```bash
source .venv/bin/activate
python main.py
```

运行后脚本会：
1. 登录 EDR（必要时多次刷新验证码）
2. 初始化 CNAPP
3. 每 2 分钟请求一次 overview API（按天/时间窗口拉取）
4. 过滤已发送 `event_id`，将新告警推送飞书

## 备注
- 若 OCR 总是识别不准，这是验证码本身“反 OCR”导致的，脚本会自动刷新多次重试。
- 若你在公司网络下 `pip install` 遇到 SSL 证书问题，可用浏览器下载 wheel 后本地安装，绕过在线拉包。
- 请妥善保管账号密码、Webhook、Secret，避免泄露。

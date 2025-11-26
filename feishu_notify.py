import time
import hmac
import base64
import hashlib
from typing import Dict, Any, List, Set

import requests

# ==================== 配置区 ====================

# 飞书自定义机器人 Webhook & Secret（签名校验）
FEISHU_WEBHOOK = " "  # TODO: 填你的 Webhook URL
FEISHU_SECRET = " "   # TODO: 填你的 Secret

# 已发送告警的 event_id 记录文件，用于去重（跨进程/重启时保持）
SENT_IDS_FILE = "sent_event_ids.txt"

# 事件等级映射
LEVEL_MAP = {
    1: "低危",
    2: "中危",
    3: "高危",
    4: "严重",
}

# ==================== 飞书相关函数 ====================

def gen_feishu_sign() -> (str, str):
    """
    生成飞书自定义机器人签名所需 timestamp 和 sign
    算法参考官方文档：timestamp + "\\n" + secret 作为 key，对空字符串做 HMAC-SHA256，然后 Base64
    """
    ts = str(int(time.time()))
    string_to_sign = f"{ts}\n{FEISHU_SECRET}"
    hmac_code = hmac.new(
        string_to_sign.encode("utf-8"),
        digestmod=hashlib.sha256
    ).digest()
    sign = base64.b64encode(hmac_code).decode("utf-8")
    return ts, sign


def build_feishu_card(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    将单条事件拼装为飞书“交互卡片”结构。
    """
    event_id = str(event.get("event_id", "")).strip()
    level = int(event.get("event_level", 0))
    level_str = LEVEL_MAP.get(level, f"未知({level})")

    ip = (event.get("terminal_internal_ip") or "").strip() or "-"
    zone = (event.get("terminal_zone_name") or "").strip() or "-"

    event_name = (event.get("event_name") or "").strip()
    event_desc = (event.get("event_desc") or "").strip()

    event_update_time_mgr = event.get("event_update_time_mgr", "")
    event_create_time_mgr = event.get("event_create_time_mgr", "")
    event_update_time_agent = event.get("event_update_time_agent", "")

    if event_name:
        title = f"【{level_str}告警】{event_name}"
    else:
        title = f"【{level_str}告警】主机{ip}存在安全事件"

    if len(title) > 80:
        title = title[:77] + "..."

    if level >= 4:
        template = "red"
    elif level == 3:
        template = "orange"
    elif level == 2:
        template = "yellow"
    else:
        template = "turquoise"

    card = {
        "config": {
            "wide_screen_mode": True,
        },
        "header": {
            "template": template,
            "title": {
                "tag": "plain_text",
                "content": title,
            },
        },
        "elements": [
            {
                "tag": "div",
                "fields": [
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**事件ID：**{event_id}",
                        },
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**等级：**{level_str}",
                        },
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**终端IP：**{ip}",
                        },
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**终端地区：**{zone}",
                        },
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**平台发现：**{event_create_time_mgr}",
                        },
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**平台最近：**{event_update_time_mgr}",
                        },
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**主机最近：**{event_update_time_agent}",
                        },
                    },
                ],
            },
            {"tag": "hr"},
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"**描述：**{event_desc or '（无）'}",
                },
            },
        ],
    }
    return card


def send_feishu_card(event: Dict[str, Any]) -> None:
    """
    调用飞书自定义机器人 Webhook 发送卡片消息
    """
    ts, sign = gen_feishu_sign()
    payload = {
        "timestamp": ts,
        "sign": sign,
        "msg_type": "interactive",
        "card": build_feishu_card(event),
    }
    resp = requests.post(FEISHU_WEBHOOK, json=payload, timeout=5)
    print(f"[Feishu] status={resp.status_code}, resp={resp.text[:200]}")

def send_feishu_text(msg: str) -> None:
    """
    使用飞书自定义机器人发送纯文本消息。
    """
    ts, sign = gen_feishu_sign()

    payload = {
        "timestamp": ts,
        "sign": sign,
        "msg_type": "text",
        "content": {
            "text": msg,
        },
    }

    try:
        resp = requests.post(FEISHU_WEBHOOK, json=payload, timeout=5)
        print(f"[Feishu] status={resp.status_code}, resp={resp.text}")
    except Exception as e:
        print(f"[Feishu] 发送失败: {e}")

# ==================== 去重相关函数 ====================

def load_sent_ids() -> Set[str]:
    """
    从本地文件读取已发送过告警的 event_id 集合
    """
    ids: Set[str] = set()
    try:
        with open(SENT_IDS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    ids.add(line)
    except FileNotFoundError:
        pass
    return ids


def append_sent_ids(new_ids: List[str]) -> None:
    """
    把本次新发送的 event_id 追加写入文件
    """
    if not new_ids:
        return
    with open(SENT_IDS_FILE, "a", encoding="utf-8") as f:
        for eid in new_ids:
            f.write(eid + "\n")


def extract_event_list(resp_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    尝试从不同结构的响应 JSON 中提取 event_list：
      1. {"code":0,"msg":"操作成功","data":{"event_list":[...]}}
      2. {"data":{"event_list":[...]}}
      3. {"event_list":[...]}
      4. 直接是一个列表 [...]
    """
    if isinstance(resp_json, list):
        return resp_json

    if "data" in resp_json and isinstance(resp_json["data"], dict):
        data = resp_json["data"]
        if "event_list" in data and isinstance(data["event_list"], list):
            return data["event_list"]

    if "event_list" in resp_json and isinstance(resp_json["event_list"], list):
        return resp_json["event_list"]

    print("[WARN] 响应中未找到 event_list，原始 keys:", list(resp_json.keys()))
    return []


def handle_events(resp_json: Dict[str, Any], sent_ids: Set[str]) -> List[str]:
    """
    从响应 JSON 中提取事件信息，按要求拼装标题和正文，通过飞书发卡片。
    使用 event_id 做去重。
    返回：本次新发送告警的 event_id 列表
    """
    events = extract_event_list(resp_json)
    print(f"[EDR] 本次响应事件数：{len(events)}")

    new_ids: List[str] = []

    for ev in events:
        eid = str(ev.get("event_id", "")).strip()
        if not eid:
            continue

        if eid in sent_ids:
            continue

        # 如需只告警中危以上，可以加等级判断：
        # level = int(ev.get("event_level", 0))
        # if level < 2:
        #     continue

        send_feishu_card(ev)
        sent_ids.add(eid)
        new_ids.append(eid)

    return new_ids

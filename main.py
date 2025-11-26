import time
import json
from datetime import datetime, timedelta

from edr_client import interactive_login, fetch_overview_events, LoginError, EdrSession
from feishu_notify import (
    load_sent_ids,
    append_sent_ids,
    handle_events, send_feishu_text,
)

# ====== 配置区 ======
USERNAME = " "     # TODO: edr用户名
PASSWORD = " "   # TODO: edr密码

POLL_INTERVAL_SECONDS = 120      # 每 2 分钟轮询一次
MAX_LIMIT_PER_CALL = 200         # 每次最多拉取 200 条告警

# 保存最近一次 API 响应的 JSON 字符串
RESP_DATA: str = ""


def get_time_range_one_day() -> (str, str):
    """
    获取过去 24 小时的时间范围字符串：
      start = now - 1 day
      end   = now
    返回格式："YYYY-MM-DD HH:MM:SS"
    """
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(days=1)
    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = end_dt.strftime("%Y-%m-%d %H:%M:%S")
    return start_str, end_str


def poll_loop(edr: EdrSession) -> None:
    """
    轮询调用 overview 接口：
      - 每次拉过去 24 小时的数据
      - 把响应 JSON 保存到 RESP_DATA 变量
      - 判断有没有新的告警，有则发飞书
      - 如果发现登录失效（401），自动重新登录后再重试一次
    """
    global RESP_DATA, USERNAME, PASSWORD

    sent_ids = load_sent_ids()
    print(f"[INIT] 已有告警事件数量：{len(sent_ids)}")

    print("[INFO] 开始进入轮询模式，每 2 分钟检查一次新告警…")

    while True:
        start_time, end_time = get_time_range_one_day()
        print(f"[INFO] 本次查询时间范围：{start_time} ~ {end_time}")

        try:
            resp_json = fetch_overview_events(
                edr,
                start_time=start_time,
                end_time=end_time,
                offset=0,
                limit=MAX_LIMIT_PER_CALL,
            )
        except Exception as e:
            msg = str(e)
            # 如果是 401 或未授权，尝试自动重新登录
            if "401" in msg or "未授权" in msg or "认证失败" in msg:
                send_feishu_text("【EDR】登录状态可能失效，将自动重新登录…")
                print("[WARN] 检测到登录状态可能失效，将自动重新登录…")
                try:
                    edr = interactive_login(
                        username=USERNAME,
                        password=PASSWORD,
                        max_attempts=50,
                        captcha_dir="./captcha",
                    )
                    # 重新登录成功后，立即再试一次 overview
                    try:
                        resp_json = fetch_overview_events(
                            edr,
                            start_time=start_time,
                            end_time=end_time,
                            offset=0,
                            limit=MAX_LIMIT_PER_CALL,
                        )
                    except Exception as e2:
                        print(f"[ERROR] 重新登录后调用 overview 仍然失败: {e2}")
                        print(f"[INFO] 休眠 {POLL_INTERVAL_SECONDS} 秒后重试…")
                        try:
                            time.sleep(POLL_INTERVAL_SECONDS)
                        except KeyboardInterrupt:
                            print("[INFO] 收到中断信号，退出轮询。")
                            break
                        continue
                except Exception as e_login:
                    print(f"[FATAL] 自动重新登录失败: {e_login}")
                    print(f"[INFO] 休眠 {POLL_INTERVAL_SECONDS} 秒后重试…")
                    try:
                        time.sleep(POLL_INTERVAL_SECONDS)
                    except KeyboardInterrupt:
                        print("[INFO] 收到中断信号，退出轮询。")
                        break
                    continue
            else:
                send_feishu_text(f"【EDR】调用 overview 接口失败: {e}")
                print(f"[ERROR] 调用 overview 接口失败: {e}")
                print(f"[INFO] 休眠 {POLL_INTERVAL_SECONDS} 秒后重试…")
                try:
                    time.sleep(POLL_INTERVAL_SECONDS)
                except KeyboardInterrupt:
                    print("[INFO] 收到中断信号，退出轮询。")
                    break
                continue

        # 把响应整体保存到 RESP_DATA 变量（代替写 req.txt）
        RESP_DATA = json.dumps(resp_json, ensure_ascii=False)

        # 调用飞书告警处理逻辑（卡片 + 去重）
        new_ids = handle_events(resp_json, sent_ids)
        append_sent_ids(new_ids)

        print(f"[DONE] 本次新发送告警数量：{len(new_ids)}")
        print(f"[INFO] 休眠 {POLL_INTERVAL_SECONDS} 秒后进行下一次轮询…")

        try:
            time.sleep(POLL_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            print("[INFO] 收到中断信号，退出轮询。")
            break


def main():
    print("[INFO] 开始登录 EDR …")
    try:
        edr = interactive_login(
            username=USERNAME,
            password=PASSWORD,
            max_attempts=50,
            captcha_dir="./captcha",
        )
    except LoginError as e:
        print(f"[FATAL] 初次登录失败: {e}")
        return

    poll_loop(edr)


if __name__ == "__main__":
    main()

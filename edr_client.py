import os
import time
import json
import binascii
from dataclasses import dataclass
from typing import Optional, Tuple

import warnings
import requests
from requests import Session

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from urllib3.exceptions import InsecureRequestWarning
import urllib3
from datetime import datetime, timedelta

from feishu_notify import send_feishu_text

# 关闭 HTTPS 未验证证书的警告
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
urllib3.disable_warnings(InsecureRequestWarning)

BASE_URL = "https://edr.chinawayltd.com"


class LoginError(Exception):
    pass


@dataclass
class EdrSession:
    session: Session
    sessionid: str
    token: str


def log_http(tag: str, resp: requests.Response,) -> None:
    """简化日志：只打印方法、URL 和状态码。 """
    req = resp.request
    print(f"[DEBUG] {tag}: {req.method} {req.url} -> HTTP {resp.status_code}")


def new_session() -> Session:
    """创建一个尽量贴近浏览器的 Session，并预先放入 hadSetUkey=0。"""
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/142.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
    })
    s.cookies.set("hadSetUkey", "0", domain="edr.chinawayltd.com", path="/")
    return s


def rsa_encrypt_password(rsa_modulus_hex: str, password: str) -> str:
    """
    用 /login rsakey 返回的十六进制模数 + 固定指数 0x10001 做 RSA/PKCS1_v1_5 加密。
    """
    n = int(rsa_modulus_hex, 16)
    e = 0x10001
    key = RSA.construct((n, e))
    cipher = PKCS1_v1_5.new(key)
    ct_bytes = cipher.encrypt(password.encode("utf-8"))
    return binascii.hexlify(ct_bytes).decode("ascii")


def default_json_headers(session: Session, referer: str) -> dict:
    """构造和浏览器尽量一致的 JSON 请求头（不包含 Cookie）。"""
    return {
        "User-Agent": session.headers["User-Agent"],
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": session.headers.get("Accept-Language", "zh-CN,zh;q=0.9"),
        "Origin": BASE_URL,
        "Referer": referer,
        "Content-Type": "application/json;charset=UTF-8",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Priority": "u=1, i",
    }


def init_anonymous_session(session: Session) -> None:
    """模拟浏览器先 GET /ui/login.php，拿到匿名 sessionid。"""
    url = f"{BASE_URL}/ui/login.php"
    headers = {
        "User-Agent": session.headers["User-Agent"],
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": session.headers["Accept-Language"],
        "Referer": f"{BASE_URL}/ui/",
    }
    resp = session.get(url, headers=headers, verify=False, timeout=10)
    log_http("INIT_LOGIN_PAGE", resp)


def download_captcha(session: Session, save_dir: str = "./captcha") -> Tuple[str, str]:
    """GET /ui/randcode.php?{ts} 下载验证码图片。"""
    ts = str(int(time.time() * 1000))
    url = f"{BASE_URL}/ui/randcode.php?{ts}"

    headers = {
        "User-Agent": session.headers["User-Agent"],
        "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "Referer": f"{BASE_URL}/ui/login.php",
        "Accept-Language": session.headers["Accept-Language"],
    }

    resp = session.get(url, headers=headers, verify=False, timeout=10)
    log_http("CAPTCHA", resp)
    resp.raise_for_status()

    os.makedirs(save_dir, exist_ok=True)
    filename = f"captcha_{ts}.png"
    filepath = os.path.join(save_dir, filename)
    with open(filepath, "wb") as f:
        f.write(resp.content)

    print(f"[INFO] 验证码图片已保存到: {filepath}")
    return filepath, ts


# ===== 本地 OCR 识别验证码 =====
from PIL import Image, ImageFilter, ImageOps
import pytesseract

def ocr_captcha(image_path: str) -> str:
    """
    使用本地 Tesseract OCR 识别验证码图片。
    验证码规则：必须是 4 位，大写字母 A-Z 或数字 0-9。
    """
    img = Image.open(image_path)

    # ===== 预处理 =====
    img = img.convert("L")  # 灰度
    w, h = img.size
    img = img.resize((w * 3, h * 3), Image.Resampling.LANCZOS)  # 放大，方便识别
    img = img.filter(ImageFilter.MedianFilter(size=3))          # 去噪
    img = ImageOps.autocontrast(img)                            # 自动对比度

    threshold = 140
    img = img.point(lambda x: 255 if x > threshold else 0, "1") # 二值化
    # =========================================================

    # 只允许 A-Z 和 0-9
    config = r"--psm 8 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    raw = pytesseract.image_to_string(img, config=config)
    print(f"[DEBUG] OCR raw result: {repr(raw)}")

    code = "".join(ch for ch in raw if ch.isalnum()).upper()
    print(f"[DEBUG] OCR cleaned code: {repr(code)}")

    # ★★ 关键逻辑：不是 4 位就认为本次 OCR 失败，抛异常 ★★
    if len(code) != 4:
        raise RuntimeError(f"OCR 识别结果不是 4 位: {repr(code)}")

    print(f"[INFO] OCR 识别验证码结果：{code}")
    return code



# ===== 登录流程相关 =====

def get_login_type(session: Session, username: str) -> None:
    """POST /launch_login.php  opr=get_login_type"""
    url = f"{BASE_URL}/launch_login.php"
    payload = {
        "opr": "get_login_type",
        "app_args": {"name": "app.web.auth.login", "options": {}},
        "name": username,
    }
    headers = default_json_headers(session, referer=f"{BASE_URL}/ui/login.php")

    resp = session.post(url, headers=headers, json=payload, verify=False, timeout=10)
    log_http("GET_LOGIN_TYPE", resp)


def get_rsa_key(session: Session) -> str:
    """POST /login  opr=rsakey"""
    url = f"{BASE_URL}/login"
    payload = {"opr": "rsakey"}
    headers = default_json_headers(session, referer=f"{BASE_URL}/ui/login.php")

    resp = session.post(url, headers=headers, json=payload, verify=False, timeout=10)
    log_http("RSAKEY", resp)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise LoginError(f"获取 rsakey 失败: {data}")
    rsa_key = data.get("key")
    if not rsa_key:
        raise LoginError(f"rsakey 响应中没有 key 字段: {data}")
    return rsa_key


def login_once_with_code(
    session: Session,
    username: str,
    password: str,
    code: str,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    用一个验证码完成一次完整登录流程。
    返回 (success, token, error_msg)
    """
    get_login_type(session, username)
    rsa_modulus_hex = get_rsa_key(session)
    enc_pwd = rsa_encrypt_password(rsa_modulus_hex, password)

    url_login = f"{BASE_URL}/login"
    payload_login = {
        "opr": "dlogin",
        "data": {
            "auth_type": "pwd",
            "user_name": username,
            "code": code,
            "pwd": enc_pwd,
        },
    }
    headers_login = default_json_headers(session, referer=f"{BASE_URL}/ui/login.php")

    resp_login = session.post(
        url_login, headers=headers_login, json=payload_login, verify=False, timeout=10
    )
    log_http("LOGIN_DLOGIN_LOGIN", resp_login)
    resp_login.raise_for_status()
    data1 = resp_login.json()

    if not data1.get("success"):
        return False, None, f"/login dlogin 返回失败: {data1}"

    key = data1.get("key")
    if key is None:
        return False, None, f"/login dlogin 返回中没有 key: {data1}"

    url_launch = f"{BASE_URL}/launch_login.php"
    payload_launch = {
        "opr": "dlogin",
        "app_args": {"name": "app.web.auth.login", "options": {}},
        "data": {
            "key": key,
            "user_aggreement_status": "true",
        },
    }
    headers_launch = default_json_headers(session, referer=f"{BASE_URL}/ui/login.php")

    resp_launch = session.post(
        url_launch, headers=headers_launch, json=payload_launch, verify=False, timeout=10
    )
    log_http("LOGIN_DLOGIN_LAUNCH", resp_launch)
    resp_launch.raise_for_status()
    data2 = resp_launch.json()

    if not data2.get("success"):
        return False, None, f"launch_login dlogin 返回失败: {data2}"

    token = None
    if isinstance(data2.get("data"), dict):
        token = data2["data"].get("token")

    if not token:
        return False, None, f"launch_login dlogin 返回中没有 token: {data2}"

    return True, token, None


def init_cnapp_session(edr: EdrSession) -> None:
    """
    CNAPP 初始化：
      - /launch.php?s={token}&opr=list_auth_info
      - /launch.php?s={token}&opr=get_version_and_service_time
    """
    session = edr.session
    token = edr.token

    session.cookies.set("hadSetUkey", "0", domain="edr.chinawayltd.com", path="/")

    headers = default_json_headers(session, referer=f"{BASE_URL}/ui/")

    def _safe_post(tag: str, url: str, payload: dict):
        body_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        try:
            resp = session.post(
                url,
                headers=headers,
                data=body_str.encode("utf-8"),
                verify=False,
                timeout=10,
            )
            log_http(tag, resp)
        except Exception as e:
            print(f"[WARN] {tag} 调用异常: {e}")

    now_ts = int(time.time() * 1000)

    url_auth = f"{BASE_URL}/launch.php?s={token}&opr=list_auth_info"
    payload_auth = {
        "app_args": {"name": "app.web.common.bubble", "option": {}},
        "opr": "list_auth_info",
        "auto": 1,
        "query_id": f"Query_{now_ts}",
    }
    _safe_post("INIT_LIST_AUTH_INFO", url_auth, payload_auth)

    url_ver = f"{BASE_URL}/launch.php?s={token}&opr=get_version_and_service_time"
    payload_ver = {
        "app_args": {"name": "app.web.event_center.head", "options": {}},
        "opr": "get_version_and_service_time",
        "query_id": f"Query_{now_ts+1}",
    }
    _safe_post("INIT_GET_VERSION_AND_SERVICE_TIME", url_ver, payload_ver)


def interactive_login(
    username: str,
    password: str,
    max_attempts: int = 5,
    captcha_dir: str = "./captcha",
) -> EdrSession:
    """
    自动登录（本地 OCR 识别验证码）：
      - OCR 识别验证码；
      - 验证码识别结果必须是 4 位，否则不计入尝试次数，直接刷新验证码重来；
      - 只有真正向 /login 发起一次登录请求，才算一次“尝试”（计入 max_attempts）；
      - 登录成功后删除本次登录过程中下载的验证码图片。
    """
    session = new_session()
    init_anonymous_session(session)

    downloaded_images = []

    # attempt 只统计“真正发起登录请求”的次数
    attempt = 0

    while attempt < max_attempts:
        print(f"[INFO] 正在进行第 {attempt + 1} 次登录尝试（OCR 识别验证码）…")

        # 每轮先拉一张新的验证码
        img_path, _ = download_captcha(session, save_dir=captcha_dir)
        downloaded_images.append(img_path)

        # 1. 先 OCR 识别验证码
        try:
            code = ocr_captcha(img_path)
        except Exception as e:
            # OCR 失败（比如不是 4 位、完全没识别到等）：
            #   不增加 attempt，不算一次尝试，直接下一轮 while（重新下载验证码）
            print(f"[ERROR] OCR 识别验证码失败: {e}")
            continue

        # 走到这里说明拿到了 4 位验证码，才算一次“真正尝试登录”
        attempt += 1

        # 2. 用识别到的验证码去走完整登录流程
        ok, token, err = login_once_with_code(
            session=session,
            username=username,
            password=password,
            code=code,
        )

        if ok and token:
            # 登录成功后访问一次 /ui/，与浏览器行为保持一致
            headers_ui = {
                "User-Agent": session.headers["User-Agent"],
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8,"
                    "application/signed-exchange;v=b3;q=0.7"
                ),
                "Accept-Language": session.headers["Accept-Language"],
                "Referer": f"{BASE_URL}/ui/login.php",
            }
            resp_ui = session.get(f"{BASE_URL}/ui/", headers=headers_ui, verify=False, timeout=10)
            log_http("AFTER_LOGIN_UI", resp_ui)

            sessionid = session.cookies.get("sessionid", "")
            print("[INFO] 登录成功。")
            print(f"[OK] 登录成功，sessionid = {sessionid}, token = {token}")

            edr = EdrSession(session=session, sessionid=sessionid, token=token)

            print("[INFO] 正在执行 CNAPP 初始化 init_cnapp_session() ...")
            init_cnapp_session(edr)
            print("[INFO] CNAPP 初始化完成。")
            send_feishu_text(f"【EDR】登录成功,尝试登录{attempt}次。")
            # 登录成功后，删除登录过程中下载的所有验证码图片
            for path in downloaded_images:
                try:
                    print(f"[INFO] 正在删除验证码图片: {path}")
                    os.remove(path)
                except OSError:
                    pass

            return edr

        # 登录没成功（比如验证码错误、密码错误等）
        print(f"[WARN] 登录失败：{err}")
        if attempt < max_attempts:
            print("[INFO] 准备重新获取验证码并再次尝试……")
    send_feishu_text("【EDR】多次尝试登录失败（共 {max_attempts} 次）。")
    raise LoginError(f"多次尝试登录失败（共 {max_attempts} 次）。")


def fetch_overview_events(
    edr: EdrSession,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    offset: int = 0,
    limit: int = 200,
    uuid: str = "sf-id-24",
    tid: str = "0",
    uid: str = "xiayingfei",
) -> dict:
    """
    调用 overview/list 接口。
    """
    # 如果未指定时间范围，默认取过去 24 小时
    if start_time is None or end_time is None:
        end_dt = datetime.now()
        start_dt = end_dt - timedelta(days=1)
        if start_time is None:
            start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        if end_time is None:
            end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    session = edr.session
    token = edr.token

    session.cookies.set("hadSetUkey", "0", domain="edr.chinawayltd.com", path="/")

    url = (
        f"{BASE_URL}/api/edrgoweb/v1/cnapp/professional/dar/overview/list"
        f"?_method=post&s={token}"
    )

    payload = {
        "offset": offset,
        "limit": limit,
        "event_type": ["all_evets"],
        "event_update_range_start": start_time,
        "event_update_range_end": end_time,
        "order_direction": "",
        "order_field": "",
        "defense_status": False,
        "is_overview": 2,
        "uuid": uuid,
        "tid": tid,
        "uid": uid,
        "token": token,
    }

    headers = default_json_headers(session, referer=f"{BASE_URL}/ui/")
    headers.update({
        "Host": "edr.chinawayltd.com",
        "Accept": "application/json, text/plain, */*",
    })

    body_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    resp = session.post(
        url,
        headers=headers,
        data=body_str.encode("utf-8"),
        verify=False,
        timeout=15,
    )
    log_http("OVERVIEW", resp)

    if resp.status_code == 401:
        print("[ERROR] overview 接口返回 401 Unauthorized")
        print("[DEBUG] 响应体前 500 字符：")
        print(resp.text[:500])
        raise RuntimeError("overview 接口 401 未授权，可能是登录状态已失效")

    resp.raise_for_status()
    data = resp.json()
    return data

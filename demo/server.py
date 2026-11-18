#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NAS 系统监控面板 · Demo 服务
============================

纯标准库实现的假后端：任意密码都能登录，所有接口返回 fixtures 里的假数据，
用来在没有 NAS 的机器上直接预览前端界面。

    python3 demo/server.py            # 默认 http://127.0.0.1:8899
    python3 demo/server.py --port 8080

不会读取任何真实主机信息，也不执行任何系统命令。
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
FIXTURES = os.path.join(BASE, "fixtures")
COOKIE = "naspanel=demo-session; Path=/; HttpOnly; SameSite=Strict"


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


# 固定返回假数据的接口
STATIC_API = {
    "/api/state": "state.json",
    "/api/disk": "disk.json",
    "/api/disk/cleanable": "cleanable.json",
}

# 演示环境里一律"操作成功"的接口
NOOP_API = {
    "/api/logout", "/api/action", "/api/disk/clean", "/api/disk/drill",
    "/api/hp/toggle", "/api/hp/subscribe", "/api/hp/test", "/api/hp/node",
    "/api/res",
}

SSH_PREFIX = "/api/ssh/"


class Handler(BaseHTTPRequestHandler):
    server_version = "nas-monitor-demo/1.0"

    def log_message(self, fmt, *args):        # 安静一点
        if os.environ.get("DEMO_VERBOSE"):
            super().log_message(fmt, *args)

    # ---------- 基础响应 ----------
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, payload, extra=None):
        self._send(code, json.dumps(payload, ensure_ascii=False), extra=extra)

    def _ok(self, data, extra=None):
        self._json(200, {"ok": True, "data": data}, extra=extra)

    def _err(self, code, message):
        self._json(code, {"ok": False, "error": message})

    # ---------- 路由 ----------
    def do_GET(self):
        path = posixpath.normpath(self.path.split("?", 1)[0])
        if path in ("/", "/index.html", "/panel"):
            return self._serve_index()
        if path.startswith("/api/"):
            return self._api(path)
        return self._err(404, "not found")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = posixpath.normpath(self.path.split("?", 1)[0])
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 1 << 20))     # 丢掉请求体
        if path == "/api/login":
            # 演示环境：任意密码都能进
            return self._ok({"user": "demo"}, {"Set-Cookie": COOKIE})
        return self._api(path)

    def _serve_index(self):
        with open(os.path.join(ROOT, "index.html"), "rb") as fh:
            self._send(200, fh.read(), "text/html; charset=utf-8",
                       {"Cache-Control": "no-store"})

    def _api(self, path):
        if path in STATIC_API:
            return self._ok(fixture(STATIC_API[path]))
        if path in NOOP_API:
            return self._ok({"demo": True})
        if path.startswith(SSH_PREFIX):
            return self._err(501, "Demo 环境不支持 Web 终端")
        return self._err(404, "unknown api: " + path)


def main():
    ap = argparse.ArgumentParser(description="NAS 系统监控面板 Demo")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8899)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Demo 已启动 → http://{args.host}:{args.port}/  （任意密码登录）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()

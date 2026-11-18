#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NAS 系统监控面板（LAN 版）
============================

功能：
  * 服务状态灯：正常=绿 / 异常=黄 / 无法服务=红 / 已关闭=灰
  * 服务启停重启（systemd 单元 + Docker 容器），只允许 start/stop/restart
  * Docker 面板：列出全部容器，可手动启动/停止/重启（无删除）
  * 网络状态：默认路由、光猫、外网、DNS、内网、IPv6、隧道、代理
  * homeproxy 管理：开关代理、改订阅链接并更新、选节点、连通性测试

安全模型：
  * 面板以 root 运行在宿主机上（等价 root 账户 SSH 登录的能力）
  * 所有写操作要求二次输入管理员密码（面板密码）
  * 只允许来自 allow_cidrs 的源地址访问
  * 代码层面不存在 rm/prune/delete 分支

纯标准库实现，无第三方依赖。
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import getpass
import hashlib
import hmac
import ipaddress
import json
import select
import termios
import os
import pty
import re
import signal
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.path.join(BASE_DIR, "panel.conf.json")
INDEX_PATH = os.path.join(BASE_DIR, "index.html")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
LOG_PATH = "/var/log/nas-panel.log"
HISTORY_PATH = os.path.join(BASE_DIR, "history.json")
HIST_INTERVAL = 120.0     # 采样间隔（秒）
HIST_KEEP = 1440          # 保留样本数（120s × 1440 = 48 小时）
HIST_BUCKETS = 48         # 返回给前端的桶数（48 × 30min = 24h）
TZ = timezone(timedelta(hours=8))

PBKDF2_ITERS = 260000
SESSION_HOURS = 12
STATE_TTL = 3.0
HP_TTL = 8.0
PROXY_TEST_TTL = 30.0
PROXY_ADDR = "http://192.168.10.1:5330"
# 连通性测试目标：百度=国内基准（直连应当通），Google/YouTube=境外基准（只有走代理才通）
PROXY_TEST_TARGETS = [
    ("baidu", "百度", "https://www.baidu.com/"),
    ("google", "Google", "https://www.google.com/generate_204"),
    ("youtube", "YouTube", "https://www.youtube.com/generate_204"),
]

PROXY_ENV_KEYS = (
    "http_proxy", "https_proxy", "all_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "no_proxy", "NO_PROXY",
)


def clean_env() -> dict:
    env = {}
    for k, v in os.environ.items():
        if k in PROXY_ENV_KEYS:
            continue
        env[k] = v
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env["LC_ALL"] = "C"
    return env


BASE_ENV = clean_env()


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------

def run(cmd, timeout=15.0, env=None):
    """执行命令，返回 (rc, stdout, stderr)。永不抛异常。"""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env=env if env is not None else BASE_ENV,
        )
        return (
            p.returncode,
            p.stdout.decode("utf-8", "replace"),
            p.stderr.decode("utf-8", "replace"),
        )
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % timeout
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def log_line(kind, msg):
    try:
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 2 * 1024 * 1024:
            os.replace(LOG_PATH, LOG_PATH + ".1")
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write("%s [%s] %s\n" % (datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S"), kind, msg))
    except Exception:
        pass


def tcp_ok(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:80]


def http_ok(url, timeout=3.0):
    """能拿到任意非 5xx 的状态码即视为服务在响应。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "nas-panel/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.status
            return code < 500, "HTTP %s" % code
    except urllib.error.HTTPError as exc:
        return exc.code < 500, "HTTP %s" % exc.code
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:80]


def listen_ok(port, timeout=5.0):
    """检查本机是否有进程监听该 TCP 端口（用于 [::] 绑定、v4 回环不可达的场景）。"""
    rc, out, _ = run(["ss", "-tln"], timeout=timeout)
    return bool(re.search(r":%d\s" % int(port), out)), ""


def ping(host, count=2, timeout=6.0):
    rc, out, _ = run(["ping", "-c", str(count), "-W", "2", "-q", host], timeout=timeout)
    loss = None
    rtt = None
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    if m:
        loss = float(m.group(1))
    m = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)", out)
    if m:
        rtt = float(m.group(2))
    return {"ok": rc == 0 and (loss is None or loss < 100.0), "loss": loss, "rtt": rtt}


def duration_cn(seconds):
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    if days:
        return "%d天%d小时" % (days, hours)
    if hours:
        return "%d小时%d分" % (hours, mins)
    return "%d分" % mins


def now_iso():
    return datetime.now(TZ).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# 密码 / 会话
# --------------------------------------------------------------------------

def hash_password(password: str, salt: bytes = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERS, salt.hex(), digest.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(digest.hex(), hash_hex)
    except Exception:  # noqa: BLE001
        return False


SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
LOGIN_FAILS = {}
LOGIN_LOCK = threading.Lock()
ACTION_HITS = {}


def ip_allowed(ip, cidrs):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def ip_key(ip):
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def new_session(ip):
    token = secrets.token_urlsafe(32)
    with SESSIONS_LOCK:
        SESSIONS[token] = {"exp": time.time() + SESSION_HOURS * 3600, "net": ip_key(ip)}
    return token


def session_valid(token, ip):
    if not token:
        return False
    with SESSIONS_LOCK:
        sess = SESSIONS.get(token)
        if not sess:
            return False
        if sess["exp"] < time.time():
            SESSIONS.pop(token, None)
            return False
        return sess["net"] == ip_key(ip)


def drop_session(token):
    with SESSIONS_LOCK:
        SESSIONS.pop(token, None)


def login_locked(ip):
    now = time.time()
    with LOGIN_LOCK:
        hits = [t for t in LOGIN_FAILS.get(ip, []) if now - t < 300]
        LOGIN_FAILS[ip] = hits
        return len(hits) >= 5


def login_failed(ip):
    with LOGIN_LOCK:
        LOGIN_FAILS.setdefault(ip, []).append(time.time())


def action_rate_ok(ip):
    now = time.time()
    with LOGIN_LOCK:
        hits = [t for t in ACTION_HITS.get(ip, []) if now - t < 60]
        if len(hits) >= 30:
            ACTION_HITS[ip] = hits
            return False
        hits.append(now)
        ACTION_HITS[ip] = hits
        return True


# --------------------------------------------------------------------------
# 注册表：服务 / 容器
# --------------------------------------------------------------------------

SERVICES = [
    # id, 名称, 分组, 类型, 目标, 探针, 说明, 风险提示, oneshot
    dict(id="docker", name="容器引擎", group="core", kind="systemd", unit="docker.service",
         probe=None, note="容器运行时（停掉等于所有容器停）", warn="停止后全部容器失联"),
    dict(id="ssh", name="SSH 服务", group="core", kind="systemd", unit="ssh.service",
         probe=("tcp", "127.0.0.1", 22), note="远程维护入口"),
    dict(id="cron", name="定时任务", group="core", kind="systemd", unit="cron.service",
         probe=None, note="计划任务调度"),
    dict(id="smb", name="SMB 共享", group="core", kind="systemd", unit="smbd.service",
         probe=None, note="局域网文件共享", warn="停止后共享盘掉线"),
    dict(id="nfs", name="NFS 共享", group="core", kind="systemd", unit="nfs-server.service",
         probe=None, note="媒体库只读挂载"),
    dict(id="cloudflared", name="Cloudflare 隧道", group="net", kind="systemd", unit="cloudflared.service",
         probe=("http", "http://127.0.0.1:20241/ready"), note="免公网 IP 的外网入口"),
    dict(id="tailscaled", name="Tailscale", group="net", kind="systemd", unit="tailscaled.service",
         probe=None, note="异网组网 / 子网路由"),
    dict(id="proxy", name="反向代理", group="net", kind="docker", container="nas-proxy",
         probe=("tcp", "127.0.0.1", 443), note="统一 80 / 443 入口", warn="停止后所有域名入口不可用"),
    dict(id="smartd", name="磁盘健康监测", group="app", kind="systemd", unit="smartd.service",
         probe=None, note="S.M.A.R.T. 告警"),
    dict(id="snapraid", name="SnapRAID 校验", group="app", kind="systemd", unit="snapraid-sync.timer",
         probe=None, note="每日校验同步"),
    dict(id="backup", name="每日备份", group="app", kind="systemd", unit="nas-backup.timer",
         probe=None, note="00:03 系统备份"),
]

CONTAINER_META = {
    "nas-proxy": dict(note="统一入口反向代理", probe=("tcp", "127.0.0.1", 443),
                      warn="停止后所有域名入口不可用"),
    "jellyfin": dict(note="媒体服务器", probe=("http", "http://192.168.10.2:8096/")),
    "qbittorrent": dict(note="下载器", probe=("http", "http://192.168.10.2:8080/")),
    "nextcloud": dict(note="私有网盘", probe=("http", "http://192.168.10.2:8443/")),
    "immich-server": dict(note="照片备份", probe=("http", "http://192.168.10.2:2283/")),
    "immich-ml": dict(note="照片 AI 识别（机器学习）"),
    "photoprism": dict(note="旧照片库（已停用）"),
    "syncthing": dict(note="多端文件同步", probe=("http", "http://192.168.10.2:8384/")),
    "homeassistant": dict(note="智能家居", probe=("http", "http://192.168.10.2:8123/")),
    "portainer": dict(note="容器管理界面", probe=("http", "http://192.168.10.2:9000/")),
    "mariadb": dict(note="nextcloud 数据库"),
    "redis": dict(note="缓存"),
}

SERVICE_BY_ID = {s["id"]: s for s in SERVICES}


def systemd_show(units):
    """批量读取 systemd 单元属性，返回 {unit: {prop: value}}。"""
    if not units:
        return {}
    props = ["Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "Result", "ActiveEnterTimestamp"]
    cmd = ["systemctl", "show"] + ["--property=" + p for p in props] + list(units)
    rc, out, err = run(cmd, timeout=10.0)
    result = {}
    cur = None
    if rc not in (0, 1):
        return result
    for line in out.splitlines():
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        if key == "Id":
            cur = val
            result[cur] = {}
            continue
        if cur:
            result[cur][key] = val
    # 补上未返回的单元
    for unit in units:
        result.setdefault(unit, {})
    return result


def docker_snapshot():
    rc, out, err = run(
        ["docker", "ps", "-a", "--format",
         "{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}"],
        timeout=12.0,
    )
    rows = []
    if rc != 0:
        return rows, err.strip()[:200]
    names = []
    for line in out.splitlines():
        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")
        name, image, state, status, ports = parts[:5]
        if not name:
            continue
        names.append(name)
        rows.append(dict(name=name, image=image, state=state, status=status,
                         ports=ports, health="none", exit="0", autoremove=False))
    if names:
        rc2, out2, _ = run(
            ["docker", "inspect", "--format",
             "{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.ExitCode}}|{{.HostConfig.AutoRemove}}"]
            + names,
            timeout=20.0,
        )
        idx = {r["name"]: r for r in rows}
        if rc2 == 0:
            for line in out2.splitlines():
                fields = line.split("|")
                if len(fields) < 4:
                    continue
                nm = fields[0].lstrip("/")
                if nm in idx:
                    idx[nm]["health"] = fields[2]
                    idx[nm]["exit"] = fields[3]
                    idx[nm]["autoremove"] = (len(fields) > 4 and fields[4].strip() == "true")
    return rows, ""


# --------------------------------------------------------------------------
# 代理（OpenWrt 容器里的 HomeProxy 包）
# --------------------------------------------------------------------------

HP_LOCK = threading.Lock()
HP_CACHE = {"ts": 0.0, "data": None}
PROXY_TEST_CACHE = {"ts": 0.0, "data": None}


# 代理跑在独立的 OpenWrt 容器里（HomeProxy 包），容器名按你的部署改这里
PROXY_CONTAINER = "proxy-router"


def _oxe(args, timeout=15.0):
    return run(["docker", "exec", PROXY_CONTAINER] + args, timeout=timeout)


def hp_config():
    rc, out, err = _oxe(["uci", "-q", "show", "homeproxy"], timeout=12.0)
    if rc != 0:
        return None, (err or out).strip()[:200]
    main, sub, routing, nodes = {}, {}, {}, {}
    for line in out.splitlines():
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        val = val.strip()
        if len(val) >= 2 and val[0] == "'" and val[-1] == "'":
            val = val[1:-1]
        parts = key.split(".")
        if len(parts) < 2:
            continue
        sec = parts[1]
        opt = parts[2] if len(parts) > 2 else None
        if opt is None:
            if val == "node":
                nodes[sec] = dict(id=sec)
            continue
        if sec == "config":
            main[opt] = val
        elif sec == "subscription":
            sub[opt] = val
        elif sec == "routing":
            routing[opt] = val
        elif sec in nodes:
            nodes[sec][opt] = val
    return dict(main=main, sub=sub, routing=routing, nodes=nodes), ""


def hp_running():
    rc, out, err = _oxe(["/etc/init.d/homeproxy", "status"], timeout=10.0)
    text = (out + err).strip()
    return rc == 0 and "running" in text, text


def hp_snapshot(force=False):
    now = time.time()
    with HP_LOCK:
        if not force and HP_CACHE["data"] and now - HP_CACHE["ts"] < HP_TTL:
            return HP_CACHE["data"]
    cfg, err = hp_config()
    running, raw = hp_running()
    data = dict(ok=cfg is not None, error=err, running=running, status_raw=raw[:120])
    if cfg:
        main, sub, routing, nodes = cfg["main"], cfg["sub"], cfg["routing"], cfg["nodes"]
        main_node = main.get("main_node", "nil")
        node_list = []
        for nid, node in nodes.items():
            node_list.append(dict(
                id=nid,
                label=node.get("label") or node.get("address") or nid[:8],
                type=node.get("type", ""),
                address=node.get("address", ""),
                port=node.get("port", ""),
            ))
        node_list.sort(key=lambda x: x["label"])
        current = next((n for n in node_list if n["id"] == main_node), None)
        data.update(
            mode=main.get("proxy_mode", ""),
            routing_mode=routing.get("routing_mode", "") or main.get("routing_mode", ""),
            ipv6=main.get("ipv6_support", "0"),
            main_node=main_node,
            main_node_label=(current["label"] if current else ("未选择" if main_node == "nil" else main_node[:8])),
            subscription=sub.get("subscription_url", ""),
            auto_update=sub.get("auto_update", "0") == "1",
            mixed_port="5330",
            nodes=node_list,
            node_count=len(node_list),
        )
    with HP_LOCK:
        HP_CACHE.update(ts=now, data=data)
    return data


def _curl(url, proxy=None, timeout=12, max_time=12):
    cmd = ["curl", "-sS", "-m", str(max_time), "-o", "-", "-w", "\n%{http_code} %{time_total}", url]
    if proxy:
        cmd[1:1] = ["-x", proxy]
    rc, out, err = run(cmd, timeout=timeout)
    code, elapsed, body = "", "", ""
    if out:
        lines = out.rstrip("\n").split("\n")
        if lines:
            tail = lines[-1].split()
            if len(tail) >= 2:
                code, elapsed = tail[0], tail[1]
                body = "\n".join(lines[:-1]).strip()
            else:
                body = out.strip()
    return dict(rc=rc, code=code, elapsed=elapsed, body=body, err=err.strip()[:120])


def _probe(url, proxy, max_time):
    """单次探测：返回 {ok, code, ms, err}。ok=HTTP 2xx/3xx（000 视为不通）。"""
    try:
        r = _curl(url, proxy, timeout=max_time + 3.0, max_time=max_time)
    except Exception as exc:  # noqa: BLE001
        return dict(ok=False, code="000", ms=None, err=str(exc)[:60])
    code = (r.get("code") or "").strip()
    ok = bool(code[:1] in ("2", "3"))
    ms = None
    try:
        ms = int(round(float(r.get("elapsed") or 0) * 1000))
    except (TypeError, ValueError):
        ms = None
    return dict(ok=ok, code=code or "000", ms=ms, err=(r.get("err") or "").strip()[:60])


def hp_test(force=False):
    """三站点（百度 / Google / YouTube）直连 vs 经代理 的连通性对比。"""
    now = time.time()
    with HP_LOCK:
        if not force and PROXY_TEST_CACHE["data"] and now - PROXY_TEST_CACHE["ts"] < PROXY_TEST_TTL:
            return PROXY_TEST_CACHE["data"]

    results = {}
    lock = threading.Lock()

    def put(key, val):
        with lock:
            results[key] = val

    def work_target(key, url, via):
        put((key, via), _probe(url, PROXY_ADDR if via else None, 7 if via else 5))

    def work_ip(key, url, proxy, max_time):
        r = _curl(url, proxy, timeout=max_time + 3.0, max_time=max_time)
        put(key, (r.get("body") or "").strip())

    threads = []
    for key, _name, url in PROXY_TEST_TARGETS:
        for via in (False, True):
            t = threading.Thread(target=work_target, args=(key, url, via), daemon=True)
            t.start()
            threads.append(t)
    t = threading.Thread(target=work_ip, args=("direct_ip", "http://ip.3322.net/", None, 6), daemon=True)
    t.start(); threads.append(t)
    t = threading.Thread(target=work_ip, args=("proxy_ip", "https://api.ipify.org", PROXY_ADDR, 10), daemon=True)
    t.start(); threads.append(t)
    for t in threads:
        t.join(14)

    def ipv4(x):
        x = (x or "").strip()
        return x if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", x) else ""

    targets, proxy_ok_all, direct_ok_all, bad = [], True, True, []
    for key, name, _url in PROXY_TEST_TARGETS:
        d = results.get((key, False)) or dict(ok=False, code="000", ms=None, err="超时")
        p = results.get((key, True)) or dict(ok=False, code="000", ms=None, err="超时")
        if not p["ok"]:
            proxy_ok_all = False
            bad.append(name)
        if not d["ok"]:
            direct_ok_all = False
        targets.append(dict(key=key, name=name, direct=d, proxy=p))

    direct_ip = ipv4(results.get("direct_ip"))
    proxy_ip = ipv4(results.get("proxy_ip"))

    if not any(t["proxy"]["ok"] for t in targets):
        note = "经代理全部失败（代理未运行或端口不通）"
    elif proxy_ok_all:
        note = "经代理三站点均可达"
    else:
        note = "经代理部分失败：" + "、".join(bad)
    if proxy_ip and direct_ip and proxy_ip == direct_ip:
        note += "（代理出口 IP 与直连相同，疑似未走代理）"

    data = dict(
        ts=now_iso(),
        ok=proxy_ok_all,
        note=note,
        targets=targets,
        direct_ip=direct_ip,
        proxy_ip=proxy_ip,
        ip=proxy_ip,                       # 兼容旧字段
        latency_ms=next((t["proxy"]["ms"] for t in targets if t["key"] == "google" and t["proxy"]["ms"]), None),
        direct_ok_all=direct_ok_all,
    )
    with HP_LOCK:
        PROXY_TEST_CACHE.update(ts=now, data=data)
    return data


def hp_toggle(enable):
    action = "start" if enable else "stop"
    rc, out, err = _oxe(["/etc/init.d/homeproxy", action], timeout=60.0)
    time.sleep(1.5)
    running, raw = hp_running()
    with HP_LOCK:
        HP_CACHE.update(ts=0.0, data=None)
        PROXY_TEST_CACHE.update(ts=0.0, data=None)
    return dict(rc=rc, output=(out + err).strip()[-600:], running=running, raw=raw[:200])


def hp_set_subscription(url):
    rc, out, err = _oxe(["sh", "-c",
                         "cp -f /etc/config/homeproxy /etc/config/homeproxy.bak-panel-$(date +%s)"], timeout=15.0)
    rc1, out1, err1 = _oxe(["uci", "set", "homeproxy.subscription.subscription_url=%s" % url], timeout=15.0)
    if rc1 != 0:
        return dict(ok=False, step="uci-set", message=(err1 or out1).strip()[:300])
    rc2, out2, err2 = _oxe(["uci", "commit", "homeproxy"], timeout=15.0)
    if rc2 != 0:
        return dict(ok=False, step="uci-commit", message=(err2 or out2).strip()[:300])
    rc3, out3, err3 = _oxe(["ucode", "-S", "/etc/homeproxy/scripts/update_subscriptions.uc"], timeout=150.0)
    rcL, outL, _ = _oxe(["tail", "-n", "30", "/var/run/homeproxy/homeproxy.log"], timeout=10.0)
    log = ((out3 + err3).strip() + "\n" + outL.strip()).strip()
    # 更新后校验 main_node 是否仍有效
    cfg, _ = hp_config()
    fixed = ""
    if cfg:
        nodes = cfg["nodes"]
        main_node = cfg["main"].get("main_node", "nil")
        if nodes and main_node not in nodes:
            pick = sorted(nodes)[0]
            _oxe(["uci", "set", "homeproxy.config.main_node=%s" % pick], timeout=10.0)
            _oxe(["uci", "commit", "homeproxy"], timeout=10.0)
            _oxe(["/etc/init.d/homeproxy", "restart"], timeout=60.0)
            fixed = "主节点已失效，自动切到 %s" % pick[:8]
        elif not nodes:
            fixed = "订阅未返回任何节点，请检查链接"
    with HP_LOCK:
        HP_CACHE.update(ts=0.0, data=None)
        PROXY_TEST_CACHE.update(ts=0.0, data=None)
    return dict(ok=rc3 == 0, step="update", rc=rc3, log=log[-1500:], fixed=fixed)


def hp_set_node(node_id):
    rc, out, err = _oxe(["uci", "set", "homeproxy.config.main_node=%s" % node_id], timeout=10.0)
    if rc != 0:
        return dict(ok=False, message=(err or out).strip()[:300])
    _oxe(["uci", "commit", "homeproxy"], timeout=10.0)
    rc2, out2, err2 = _oxe(["/etc/init.d/homeproxy", "restart"], timeout=60.0)
    with HP_LOCK:
        HP_CACHE.update(ts=0.0, data=None)
    return dict(ok=rc2 == 0, output=(out2 + err2).strip()[-400:])


# --------------------------------------------------------------------------
# 网络 / 主机
# --------------------------------------------------------------------------

def dns_probe(name="www.baidu.com", timeout=4.0):
    def _resolve():
        return socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_resolve)
        try:
            fut.result(timeout=timeout)
            return True, ""
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)[:80]


def ipv6_probe():
    rc, out, _ = run(["ip", "-6", "addr", "show", "dev", "enp3s0", "scope", "global"], timeout=5.0)
    m = re.search(r"inet6\s+([0-9a-f:]+)/", out)
    gua = m.group(1) if m else ""
    state, detail = "unknown", "看门狗状态未知"
    try:
        with open("/var/lib/nas-v6-watch/state.json", "r", encoding="utf-8") as fh:
            st = json.load(fh)
        stt = st.get("state", "")
        if stt == "OK":
            state, detail = "ok", "外部探测正常（%s）" % (st.get("last_run", "")[:16].replace("T", " "))
        elif stt == "FAIL":
            state, detail = "fail", "外部探测失败（%s）" % (st.get("last_run", "")[:16].replace("T", " "))
        else:
            detail = "看门狗状态：%s" % stt
    except Exception:  # noqa: BLE001
        pass
    return dict(gua=gua, state=state, detail=detail)


CPU_LOCK = threading.Lock()
_CPU_PREV = {"idle": None, "total": None}


def _cpu_snapshot():
    """读 /proc/stat 第一行，返回 (idle, total) 累计值。"""
    with open("/proc/stat", "r", encoding="utf-8") as fh:
        parts = fh.readline().split()
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)  # idle + iowait
    return idle, sum(nums)


def cpu_info():
    """两次采样求差算 CPU 使用率；首次调用没有基线，用 1 分钟负载估算。"""
    info = dict(cores=os.cpu_count() or 4, pct=None)
    try:
        idle, total = _cpu_snapshot()
    except Exception:  # noqa: BLE001
        return info
    with CPU_LOCK:
        prev_idle, prev_total = _CPU_PREV["idle"], _CPU_PREV["total"]
        _CPU_PREV["idle"], _CPU_PREV["total"] = idle, total
    if prev_idle is not None and total > prev_total:
        d_total = total - prev_total
        d_idle = idle - prev_idle
        if d_total > 0:
            info["pct"] = round((1.0 - float(d_idle) / d_total) * 100.0, 1)
            return info
    try:
        info["pct"] = round(min(100.0, os.getloadavg()[0] / info["cores"] * 100.0), 1)
    except Exception:  # noqa: BLE001
        info["pct"] = 0.0
    return info


def host_info():
    info = dict(hostname=socket.gethostname(), kernel=os.uname().release)
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    info["os"] = line.split("=", 1)[1].strip().strip('"')
                    break
    except Exception:  # noqa: BLE001
        pass
    try:
        info["load"] = [round(x, 2) for x in os.getloadavg()]
    except Exception:  # noqa: BLE001
        info["load"] = [0, 0, 0]
    try:
        info["cpu"] = cpu_info()
    except Exception:  # noqa: BLE001
        info["cpu"] = dict(cores=os.cpu_count() or 4, pct=None)
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            info["uptime"] = duration_cn(float(fh.read().split()[0]))
    except Exception:  # noqa: BLE001
        info["uptime"] = ""
    mem = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                key, val = line.split(":", 1)
                mem[key.strip()] = int(val.strip().split()[0]) * 1024
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", 0)
        used = max(0, total - avail)
        info["mem"] = dict(total=total, used=used, pct=round(used * 100.0 / total, 1) if total else 0)
        st_total = mem.get("SwapTotal", 0)
        st_free = mem.get("SwapFree", 0)
        info["swap"] = dict(total=st_total, used=max(0, st_total - st_free),
                            pct=round((st_total - st_free) * 100.0 / st_total, 1) if st_total else 0)
    except Exception:  # noqa: BLE001
        info["mem"] = dict(total=0, used=0, pct=0)
        info["swap"] = dict(total=0, used=0, pct=0)
    try:
        usage = shutil.disk_usage("/")
        info["disk"] = dict(total=usage.total, used=usage.used,
                            pct=round(usage.used * 100.0 / usage.total, 1))
    except Exception:  # noqa: BLE001
        info["disk"] = dict(total=0, used=0, pct=0)
    return info


def network_state(proxy):
    items = []
    rc, out, _ = run(["ip", "-4", "route", "show", "default"], timeout=5.0)
    has_default = bool(re.search(r"default via", out))
    m = re.search(r"default via ([\d.]+) dev (\S+)(?:.*metric (\d+))?", out)
    route_detail = ("→ %s dev %s" % (m.group(1), m.group(2))) if m else "无默认路由"

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_gw = pool.submit(ping, "192.168.1.1")
        f_wan = pool.submit(ping, "223.5.5.5")
        f_lan = pool.submit(ping, "192.168.10.1")
        f_dns = pool.submit(dns_probe)
        gw, wan, lan, dns = f_gw.result(), f_wan.result(), f_lan.result(), f_dns.result()

    items.append(dict(id="route", label="默认路由", status="green" if has_default else "red",
                      detail=route_detail))
    items.append(dict(id="gw", label="光猫 192.168.1.1",
                      status="green" if gw["ok"] else "red",
                      detail=("延迟 %.0fms" % gw["rtt"]) if gw["rtt"] else "不通"))
    items.append(dict(id="wan", label="外网 IPv4（223.5.5.5）",
                      status="green" if wan["ok"] else "red",
                      detail=("延迟 %.0fms" % wan["rtt"]) if wan["rtt"] else "丢包/不通"))
    items.append(dict(id="dns", label="DNS 解析", status="green" if dns[0] else "red",
                      detail="www.baidu.com 正常" if dns[0] else (dns[1] or "解析失败")))
    items.append(dict(id="lan", label="内网网关 192.168.10.1",
                      status="green" if lan["ok"] else "red",
                      detail=("延迟 %.0fms" % lan["rtt"]) if lan["rtt"] else "不通"))

    ok_http, http_detail = http_ok("http://connect.rom.miui.com/generate_204", timeout=4.0)
    items.append(dict(id="internet", label="互联网 HTTP",
                      status="green" if ok_http else "red",
                      detail="204 探测通过" if ok_http else http_detail))

    v6 = ipv6_probe()
    v6_status = {"ok": "green", "fail": "red"}.get(v6["state"], "yellow")
    if not v6["gua"]:
        v6_status, v6["detail"] = "red", "enp3s0 上没有全局 IPv6 地址"
    items.append(dict(id="ipv6", label="IPv6 直连（nas.example.com）",
                      status=v6_status, detail=v6["detail"][:60]))

    tun_ok, tun_detail = http_ok("http://127.0.0.1:20241/ready", timeout=3.0)
    items.append(dict(id="tunnel", label="Cloudflare 隧道",
                      status="green" if tun_ok else "red",
                      detail="cloudflared ready" if tun_ok else tun_detail))

    pt = proxy.get("test") or {}
    if not proxy.get("running"):
        items.append(dict(id="proxy", label="homeproxy 代理", status="gray",
                          detail="代理服务已关闭"))
    elif pt.get("ok"):
        items.append(dict(id="proxy", label="homeproxy 代理", status="green",
                          detail="出口 %s（%sms）" % (pt.get("ip", "?"), pt.get("latency_ms") or "?")))
    else:
        items.append(dict(id="proxy", label="homeproxy 代理", status="yellow",
                          detail=(pt.get("note") or "代理连通性未知")[:60]))

    order = {"red": 0, "yellow": 1, "gray": 2, "green": 3}
    worst = min((i["status"] for i in items), key=lambda s: order[s], default="green")
    if any(i["status"] == "red" for i in items if i["id"] in ("wan", "route", "gw")):
        overall = "red"
    elif worst == "red":
        overall = "yellow"
    elif worst == "yellow":
        overall = "yellow"
    else:
        overall = "green"
    return dict(status=overall, items=items)


# --------------------------------------------------------------------------
# 状态汇总
# --------------------------------------------------------------------------

STOPS_PATH = os.path.join(BASE_DIR, "state-stops.json")
STOPS_LOCK = threading.Lock()


def _load_stops():
    try:
        with open(STOPS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {}


def record_stop(name, stopped=True):
    """记录/清除"由面板主动停止"的容器，用于区分 已关闭(灰) 与 异常退出(红)。"""
    with STOPS_LOCK:
        data = _load_stops()
        if stopped:
            data[name] = time.time()
        else:
            data.pop(name, None)
        try:
            with open(STOPS_PATH, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.chmod(STOPS_PATH, 0o600)
        except Exception:  # noqa: BLE001
            pass


STATE_LOCK = threading.Lock()
STATE_CACHE = {"ts": 0.0, "data": None}


def _service_status(meta, sd, probe_res):
    kind = meta["kind"]
    entry = dict(
        id=meta["id"], name=meta["name"], group=meta.get("group", "app"),
        kind=kind, note=meta.get("note", ""), warn=meta.get("warn", ""),
        actions=[], detail="", status="gray",
    )
    if kind == "process":
        ok, msg = probe_res.get(("svc", meta["id"]), (False, "未探测"))
        entry["status"] = "green" if ok else "red"
        entry["detail"] = "进程/端口在" if ok else ("不可用：%s" % msg)
        entry["actions"] = []
        return entry

    st = sd.get(meta["unit"], {})
    load_state = st.get("LoadState", "")
    if load_state == "not-found":
        return None
    active = st.get("ActiveState", "inactive")
    sub = st.get("SubState", "")
    enabled = st.get("UnitFileState", "")
    result = st.get("Result", "")
    probe = probe_res.get(("svc", meta["id"]))
    probe_txt = ""
    if probe:
        probe_txt = " · 探测正常" if probe[0] else " · 探测失败(%s)" % probe[1][:40]

    if active == "active":
        if probe and not probe[0]:
            entry["status"] = "yellow"
        else:
            entry["status"] = "green"
        entry["detail"] = "%s（%s）· %s%s" % (active, sub, enabled or "static", probe_txt)
        entry["actions"] = ["stop", "restart"] + (["start"] if meta.get("oneshot") else [])
    elif active == "failed":
        entry["status"] = "red"
        entry["detail"] = "failed（%s）· %s%s" % (sub, result or "", probe_txt)
        entry["actions"] = ["start", "restart"]
    else:  # inactive / activating / deactivating
        if active == "activating":
            entry["status"] = "yellow"
            entry["detail"] = "启动中（%s）" % sub
            entry["actions"] = ["restart", "stop"]
        elif meta.get("oneshot") and result == "success":
            entry["status"] = "gray"
            entry["detail"] = "已执行完成（oneshot）%s" % probe_txt
            entry["actions"] = ["start"]
        else:
            entry["status"] = "gray"
            entry["detail"] = "已关闭（%s）%s" % (active, probe_txt)
            entry["actions"] = ["start"]
    return entry


def _container_status(row):
    meta = CONTAINER_META.get(row["name"], {})
    state = row.get("state", "")
    health = row.get("health", "none")
    try:
        exit_code = int(row.get("exit") or 0)
    except ValueError:
        exit_code = 0
    probe = meta.get("probe")
    probe_txt = ""
    probe_ok = True
    if probe:
        if probe[0] == "tcp":
            probe_ok, msg = tcp_ok(probe[1], probe[2])
        elif probe[0] == "listen":
            probe_ok, msg = listen_ok(probe[1])
        else:
            probe_ok, msg = http_ok(probe[1])
        probe_txt = " · 探针正常" if probe_ok else " · 探针失败(%s)" % msg[:40]

    entry = dict(
        name=row["name"], image=row.get("image", ""), state=state,
        health=health, uptime=row.get("status", ""), ports=row.get("ports", ""),
        note=meta.get("note", ""), warn=meta.get("warn", ""), detail="",
        autoremove=bool(row.get("autoremove")),
        actions=["start", "stop", "restart"],
    )
    if state == "running":
        if health == "unhealthy" or (probe and not probe_ok):
            entry["status"] = "yellow"
        else:
            entry["status"] = "green"
        entry["detail"] = ("health: %s" % health if health != "none" else "running") + probe_txt
        entry["actions"] = ["stop", "restart"]
    elif state == "restarting":
        entry["status"] = "red"
        entry["detail"] = "反复重启中" + probe_txt
        entry["actions"] = ["stop", "restart"]
    elif state in ("exited", "dead"):
        manual = bool(_load_stops().get(row["name"]))
        if state == "dead":
            entry["status"] = "red"
            entry["detail"] = "dead（守护进程异常）" + probe_txt
            entry["actions"] = ["start", "restart"]
        elif manual or exit_code == 0:
            entry["status"] = "gray"
            entry["detail"] = ("已手动停止" if manual else "已关闭（exit=0）")
            entry["actions"] = ["start"]
        else:
            entry["status"] = "red"
            entry["detail"] = "异常退出（exit=%d）" % exit_code
            entry["actions"] = ["start", "restart"]
    elif state == "paused":
        entry["status"] = "yellow"
        entry["detail"] = "已暂停"
        entry["actions"] = ["stop", "restart"]
    elif state == "created":
        entry["status"] = "gray"
        entry["detail"] = "已创建未运行"
        entry["actions"] = ["start"]
    else:
        entry["status"] = "yellow"
        entry["detail"] = state
    if entry.get("autoremove"):
        entry["actions"] = []
        entry["detail"] = "临时容器（--rm，停止即删除）· " + entry["detail"]
        entry["warn"] = "该容器以 --rm 运行，停止/重启会导致容器被删除，面板已禁用其操作"
    return entry


# ---------- 系统信息（OS / 更新 / 物理网口）----------
SYS_UP_LOCK = threading.Lock()
SYS_UP_CACHE = {"ts": 0.0, "data": None, "running": False}
SYS_UP_TTL = 1800.0


def _apt_upgradable():
    """apt-get -s upgrade 解析：返回 (可更新数, 安全更新数, 包名, 错误)"""
    rc, out, err = run(["apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "upgrade"],
                       timeout=120.0, env=dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C"))
    if rc != 0 and not out.strip():
        return None, 0, [], (err or "apt-get 执行失败").strip()[:200]
    pkgs, sec = [], set()
    for line in out.splitlines():
        if not line.startswith("Inst "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[1]
        pkgs.append(name)
        if "security" in line.lower():
            sec.add(name)
    return len(pkgs), len(sec), pkgs[:40], None


def _sys_update_probe():
    n, sec, pkgs, err = _apt_upgradable()
    data = dict(count=n, security=sec, packages=pkgs, error=err, checked=now_iso())
    with SYS_UP_LOCK:
        SYS_UP_CACHE.update(ts=time.time(), data=data, running=False)


def _spawn_update_probe():
    with SYS_UP_LOCK:
        if SYS_UP_CACHE["running"]:
            return
        SYS_UP_CACHE["running"] = True
    threading.Thread(target=_sys_update_probe, daemon=True, name="sys-update-probe").start()


def _last_system_update():
    """系统最后一轮包管理动作的时间：dpkg 状态文件 mtime 与 apt history 取最新"""
    ts = 0.0
    for path in ("/var/lib/dpkg/status", "/var/lib/apt/extended_states"):
        try:
            ts = max(ts, os.path.getmtime(path))
        except OSError:
            pass
    try:
        with open("/var/log/apt/history.log", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("Start-Date:"):
                    raw = line.split(":", 1)[1].strip().replace("  ", " ")
                    try:
                        ts = max(ts, time.mktime(time.strptime(raw, "%Y-%m-%d %H:%M:%S")))
                    except ValueError:
                        pass
    except OSError:
        pass
    return ts


IFACE_MAX_CACHE = {}


def _ethtool_max_speed(name):
    """网卡支持的最高速率（Mbps）。ethtool 输出稳定，按接口名永久缓存。"""
    if name in IFACE_MAX_CACHE:
        return IFACE_MAX_CACHE[name]
    best = None
    rc, out, _ = run(["ethtool", name], timeout=3.0)
    if rc == 0:
        in_block = False
        for line in out.splitlines():
            low = line.strip()
            if low.startswith("Supported link modes:"):
                in_block = True
                low = low.split(":", 1)[1]
            elif in_block and (line.startswith("\t\t") or line.startswith("                         ")):
                pass
            elif in_block:
                in_block = False
            for m in re.finditer(r"(\d+)base", low):
                val = int(m.group(1))
                if best is None or val > best:
                    best = val
    IFACE_MAX_CACHE[name] = best
    return best


def _phys_ifaces():
    """只取真实物理网卡（/sys/class/net/*/device 存在），含连接状态与协商速率"""
    out = []
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return out
    ipmap = {}
    rc, iout, _ = run(["ip", "-4", "-o", "addr", "show"], timeout=5.0)
    if rc == 0:
        for line in iout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet":
                ipmap.setdefault(parts[1], parts[3].split("/")[0])
    for name in names:
        base = os.path.join("/sys/class/net", name)
        if not os.path.exists(os.path.join(base, "device")):
            continue

        def rd(attr, default=""):
            try:
                with open(os.path.join(base, attr), "r") as fh:
                    return fh.read().strip()
            except OSError:
                return default

        state = rd("operstate", "unknown")
        try:
            speed = int(rd("speed", "-1"))
        except ValueError:
            speed = -1
        try:
            mtu = int(rd("mtu", "0"))
        except ValueError:
            mtu = 0
        carrier = rd("carrier") == "1"
        cur = speed if speed > 0 else None
        vmax = _ethtool_max_speed(name)
        # 三态：ok=活跃 / warn=已连接但工作不正常 / down=未连接
        if not carrier or state == "down":
            status = "down"
        elif state != "up" or cur is None:
            status = "warn"
        elif vmax and cur * 10 <= vmax:
            status = "warn"          # 协商速率不到上限的 1/10：典型线序/接触不良
        else:
            status = "ok"
        out.append(dict(
            name=name, state=state, up=(state == "up"), carrier=carrier, status=status,
            speed=cur, speed_max=vmax, mac=rd("address"), mtu=mtu,
            ipv4=ipmap.get(name, ""),
        ))
    return out


PKG_TOTAL_CACHE = {"mtime": -1.0, "count": None}


def _installed_package_count():
    """已安装软件包数量（按 dpkg status 里 install ok installed 计），按文件 mtime 缓存。"""
    try:
        mt = os.stat("/var/lib/dpkg/status").st_mtime
    except OSError:
        return None
    if PKG_TOTAL_CACHE["count"] is not None and PKG_TOTAL_CACHE["mtime"] == mt:
        return PKG_TOTAL_CACHE["count"]
    n = 0
    try:
        with open("/var/lib/dpkg/status", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Status: install ok installed"):
                    n += 1
    except OSError:
        return None
    PKG_TOTAL_CACHE["count"] = n
    PKG_TOTAL_CACHE["mtime"] = mt
    return n


def sys_snapshot():
    info = dict(kernel=os.uname().release, hostname=socket.gethostname(), os="")
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    info["os"] = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        pass
    info["last_update"] = _last_system_update()
    info["reboot_required"] = os.path.exists("/var/run/reboot-required")
    with SYS_UP_LOCK:
        data, ts = SYS_UP_CACHE["data"], SYS_UP_CACHE["ts"]
    if data is None or time.time() - ts > SYS_UP_TTL:
        _spawn_update_probe()
    info["updates"] = data
    info["pkg_total"] = _installed_package_count()
    info["ifaces"] = _phys_ifaces()
    return info


def build_state(force=False):
    now = time.time()
    with STATE_LOCK:
        if not force and STATE_CACHE["data"] and now - STATE_CACHE["ts"] < STATE_TTL:
            return STATE_CACHE["data"]

    sd = systemd_show([s["unit"] for s in SERVICES if s["kind"] == "systemd"])
    rows, docker_err = docker_snapshot()

    probes = []
    for svc in SERVICES:
        if svc.get("probe"):
            probes.append(("svc", svc["id"], svc["probe"]))
    for row in rows:
        meta = CONTAINER_META.get(row["name"], {})
        if meta.get("probe"):
            probes.append(("ct", row["name"], meta["probe"]))

    results = {}

    def _do(key, probe):
        if probe[0] == "tcp":
            return key, tcp_ok(probe[1], probe[2])
        if probe[0] == "listen":
            return key, listen_ok(probe[1])
        return key, http_ok(probe[1])

    if probes:
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = [pool.submit(_do, (kind, ident), probe) for kind, ident, probe in probes]
            for fut in futs:
                try:
                    key, val = fut.result(timeout=8)
                    results[key] = val
                except Exception:  # noqa: BLE001
                    pass

    services = []
    for svc in SERVICES:
        entry = _service_status(svc, sd, results)
        if entry:
            services.append(entry)

    containers = [_container_status(row) for row in rows]
    containers.sort(key=lambda c: (0 if c["status"] in ("red", "yellow") else 1, c["name"]))

    proxy = hp_snapshot()
    # 只在“有缓存”时附带测试结果：/api/state 必须快（不阻塞做网络探测），
    # 真正发起探测走 /api/hp/test（按钮触发）
    if proxy.get("running"):
        with HP_LOCK:
            cached = PROXY_TEST_CACHE["data"]
        proxy["test"] = dict(cached) if cached else None
    else:
        proxy["test"] = None
    net = network_state(proxy)

    state = dict(
        ts=now_iso(),
        host=host_info(),
        sys=sys_snapshot(),
        network=net,
        proxy=proxy,
        services=services,
        containers=containers,
        docker_error=docker_err,
        history=hist_series(),
        traffic=traffic_state(),
        counts=dict(
            services=len(services),
            green=len([s for s in services + containers if s["status"] == "green"]),
            yellow=len([s for s in services + containers if s["status"] == "yellow"]),
            red=len([s for s in services + containers if s["status"] == "red"]),
            gray=len([s for s in services + containers if s["status"] == "gray"]),
            containers=len(containers),
        ),
    )
    with STATE_LOCK:
        STATE_CACHE.update(ts=now, data=state)
    return state


def invalidate_state():
    with STATE_LOCK:
        STATE_CACHE.update(ts=0.0, data=None)


# --------------------------------------------------------------------------
# SSH 终端：本地 pty 里跑系统 ssh 客户端，登录 127.0.0.1
# --------------------------------------------------------------------------

SSH_MAX_SESSIONS = 2
SSH_IDLE_SECONDS = 900.0
SSH_LOGIN_TIMEOUT = 12.0
SSH_RUN_TIMEOUT = 30.0
SSH_OUTPUT_LIMIT = 200 * 1024

SSH_SESSIONS = {}
SSH_LOCK = threading.Lock()
SSH_PEER = "127.0.0.1"


class SshSession(object):
    def __init__(self, sid, user, pid, fd):
        self.id = sid
        self.user = user
        self.pid = pid
        self.fd = fd
        self.lock = threading.Lock()
        self.alive = True
        self.last = time.time()
        self.opened = now_iso()

    def poke(self):
        self.last = time.time()

    def read_for(self, timeout, until=None):
        """读 fd，最多 timeout 秒；until 为正则时命中即返回。"""
        buf = b""
        end = time.time() + timeout
        while True:
            left = end - time.time()
            if left <= 0:
                break
            try:
                r, _, _ = select.select([self.fd], [], [], min(left, 0.2))
            except (OSError, ValueError):
                break
            if not r:
                if not self.alive:
                    break
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                break
            if not chunk:
                self.alive = self.proc_alive()
                break
            buf += chunk
            if len(buf) > SSH_OUTPUT_LIMIT:
                break
            if until is not None and until.search(buf):
                break
        return buf

    def proc_alive(self):
        try:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
            return pid == 0
        except OSError:
            return False

    def drain(self, total, idle=0.25):
        """把积压输出读掉丢弃，直到安静 idle 秒或超过 total 秒。"""
        end = time.time() + total
        last = time.time()
        while time.time() < end:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.1)
            except (OSError, ValueError):
                return
            if not r:
                if time.time() - last >= idle:
                    return
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            last = time.time()

    def write(self, data):
        try:
            os.write(self.fd, data if isinstance(data, bytes) else data.encode("utf-8"))
            return True
        except OSError:
            self.alive = False
            return False

    def kill(self):
        self.alive = False
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass


def _strip_ssh_text(raw):
    """去掉 pty 里的回车与 ANSI 控制序列，保留可读文本。"""
    text = raw.decode("utf-8", "replace")
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\x1b[()][A-Za-z0-9]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def ssh_open(user, password):
    """登录 127.0.0.1，返回 (session, note)。失败抛 ValueError。"""
    user = str(user or "").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user or ""):
        raise ValueError("账号格式不对")
    if not password:
        raise ValueError("请输入密码")
    with SSH_LOCK:
        live = [x for x in SSH_SESSIONS.values() if x.alive]
        if len(live) >= SSH_MAX_SESSIONS:
            raise ValueError("已打开的终端太多（上限 %d），先断开一个" % SSH_MAX_SESSIONS)

    argv = [
        "ssh", "-tt",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=6",
        "%s@%s" % (user, SSH_PEER),
    ]
    pid, fd = pty.fork()
    if pid == 0:  # 子进程
        try:
            os.environ.update(TERM="dumb", LANG="C.UTF-8", LC_ALL="C.UTF-8")
            os.execvp(argv[0], argv)
        except Exception:  # noqa: BLE001
            os._exit(127)

    tok = secrets.token_hex(4)
    sess = SshSession(secrets.token_urlsafe(12), user, pid, fd)
    try:
        head = sess.read_for(SSH_LOGIN_TIMEOUT, until=re.compile(rb"[Pp]assword:|Permission denied"))
        blob = _strip_ssh_text(head)
        if b"Permission denied" in head and b"assword" not in head:
            raise ValueError(blob.strip().splitlines()[-1] if blob.strip() else "连接被拒绝")
        if not re.search(r"[Pp]assword:", blob):
            raise ValueError("没等到密码提示：" + (blob.strip()[-200:] or "无输出"))

        sess.write(password + "\n")
        # 登录成功后会吐 MOTD / 欢迎横幅，先排空，再关掉远端回显与提示符
        sess.drain(4.0, idle=0.45)
        if not sess.proc_alive():
            raise ValueError("账号或密码不正确")
        sess.write("stty -echo; PS1=''; PS2=''; unset PROMPT_COMMAND; export TERM=dumb\n")
        sess.drain(1.5, idle=0.35)
        # 握手：关掉回显后，marker 只可能来自命令输出（不会再命中回显）
        marker = "__P_READY_%s__" % tok
        sess.write("echo %s\n" % marker)
        tail = sess.read_for(6.0, until=re.compile(re.escape(marker).encode()))
        text = _strip_ssh_text(tail)
        if "Permission denied" in text or "Authentication failed" in text:
            raise ValueError("账号或密码不正确")
        if marker not in text:
            raise ValueError("登录未完成：" + (text.strip()[-200:] or "无输出"))
        sess.drain(0.6)
    except ValueError:
        sess.kill()
        with SSH_LOCK:
            pass
        raise
    except Exception as exc:  # noqa: BLE001
        sess.kill()
        raise ValueError("连接失败：%s" % exc)

    with SSH_LOCK:
        SSH_SESSIONS[sess.id] = sess
    log_line("SSH", "open user=%s sid=%s" % (user, sess.id[:8]))
    return sess


def ssh_run(sid, cmd):
    with SSH_LOCK:
        sess = SSH_SESSIONS.get(sid or "")
    if not sess or not sess.alive:
        raise ValueError("终端已断开，请重新连接")
    cmd = str(cmd or "")
    if len(cmd) > 4000:
        raise ValueError("单条命令过长")
    tok = secrets.token_hex(4)
    with sess.lock:
        sess.poke()
        sess.drain(0.2, idle=0.12)
        payload = (
            "printf '__P_S_%s__\\n'\n( %s\n) 2>&1\nprintf '__P_E_%s_%%d__\\n' \"$?\"\n"
            % (tok, cmd, tok)
        )
        if not sess.write(payload):
            raise ValueError("写入失败，终端可能已断开")
        done = re.compile((r"__P_E_%s_(\d+)__" % tok).encode())
        raw = sess.read_for(SSH_RUN_TIMEOUT, until=done)
    text = _strip_ssh_text(raw)
    m = done.search(text.encode("utf-8", "replace"))
    code = 0
    if m:
        code = int(m.group(1).decode())
        text = text[: m.start()]
    start = text.find("__P_S_%s__" % tok)
    if start >= 0:
        text = text[start + len("__P_S_%s__" % tok):]
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    text = "\n".join(lines).rstrip()
    truncated = len(raw) >= SSH_OUTPUT_LIMIT
    if not m:
        note = "命令超时（%ds）或输出过大，已中断；交互式程序（vim/top）请用非交互写法" % int(SSH_RUN_TIMEOUT)
        sess.alive = False
        sess.kill()
        with SSH_LOCK:
            SSH_SESSIONS.pop(sess.id, None)
        return dict(output=text, code=None, timeout=True, note=note, truncated=truncated, alive=False)
    return dict(output=text, code=code, timeout=False, note="", truncated=truncated, alive=True)


def ssh_close(sid):
    with SSH_LOCK:
        sess = SSH_SESSIONS.pop(sid or "", None)
    if sess:
        sess.kill()
        log_line("SSH", "close sid=%s" % sess.id[:8])
        return True
    return False


def ssh_close_all():
    with SSH_LOCK:
        items = list(SSH_SESSIONS.values())
        SSH_SESSIONS.clear()
    for sess in items:
        sess.kill()


def start_ssh_sweeper():
    def _loop():
        while True:
            time.sleep(30)
            now = time.time()
            dead = []
            with SSH_LOCK:
                for sid, sess in list(SSH_SESSIONS.items()):
                    if (not sess.alive) or (now - sess.last > SSH_IDLE_SECONDS):
                        dead.append(SSH_SESSIONS.pop(sid))
            for sess in dead:
                sess.kill()
                log_line("SSH", "reap sid=%s idle=%ds" % (sess.id[:8], int(now - sess.last)))

    t = threading.Thread(target=_loop, name="ssh-sweeper", daemon=True)
    t.start()
    return t


# --------------------------------------------------------------------------
# SSH 真 TTY 终端（供前端 xterm.js 使用）
# --------------------------------------------------------------------------
TERM_MAX_SESSIONS = 2
TERM_IDLE_SECONDS = 900.0
TERM_BUF_LIMIT = 256 * 1024
TERM_READ_LIMIT = 64 * 1024
TERM_SESSIONS = {}
TERM_LOCK = threading.Lock()


class TermSession(object):
    """一个 pty 里跑的真 ssh 会话；输出进环形缓冲，前端按 offset 增量拉取。"""

    def __init__(self, sid, user, password, cols, rows):
        self.id = sid
        self.user = user
        self.cols = int(cols)
        self.rows = int(rows)
        self.opened = now_iso()
        self.alive = True
        self.last = time.time()
        self.lock = threading.Lock()
        self.buf = bytearray()
        self.base = 0          # buf[0] 对应的绝对偏移
        self.closed = False
        self.prompts = 0
        self.authed = False
        self.auth_failed = False
        self._pw = password
        self.pid, self.fd = pty.fork()
        if self.pid == 0:      # 子进程：只做 exec
            try:
                os.environ.update({
                    "TERM": "xterm-256color",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                })
                os.execvp("ssh", [
                    "ssh", "-tt",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "GlobalKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-o", "NumberOfPasswordPrompts=3",
                    "-o", "PreferredAuthentications=password",
                    "-o", "PubkeyAuthentication=no",
                    "-o", "ConnectTimeout=6",
                    "-o", "ServerAliveInterval=30",
                    "{}@127.0.0.1".format(user),
                ])
            except Exception:  # noqa: BLE001
                os._exit(127)
        self._set_size(self.cols, self.rows)
        self.th = threading.Thread(target=self._reader, name="term-%s" % sid[:8], daemon=True)
        self.th.start()

    # ---- pty 操作 ----
    def _set_size(self, cols, rows):
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", max(1, rows), max(1, cols), 0, 0))
            os.kill(self.pid, signal.SIGWINCH)
        except Exception:  # noqa: BLE001
            pass

    def resize(self, cols, rows):
        self.cols, self.rows = max(1, int(cols)), max(1, int(rows))
        self._set_size(self.cols, self.rows)

    def write(self, data):
        self.last = time.time()
        try:
            os.write(self.fd, data)
        except OSError:
            self.alive = False

    def read(self, off):
        with self.lock:
            if off < self.base:
                off = self.base
            start = off - self.base
            chunk = bytes(self.buf[start:start + TERM_READ_LIMIT])
            newoff = off + len(chunk)
        return chunk, newoff

    def proc_alive(self):
        try:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            return False
        return pid == 0

    def kill(self):
        self.alive = False
        self.closed = True
        try:
            os.kill(self.pid, signal.SIGKILL)
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(self.fd)
        except Exception:  # noqa: BLE001
            pass

    # ---- 后台读线程 ----
    def _reader(self):
        while True:
            try:
                ready, _, _ = select.select([self.fd], [], [], 0.2)
                if not ready:
                    if not self.proc_alive():
                        break
                    continue
                data = os.read(self.fd, 65536)
            except (OSError, ValueError):
                break
            if not data:
                break
            self.last = time.time()
            with self.lock:
                self.buf.extend(data)
                if len(self.buf) > TERM_BUF_LIMIT:
                    cut = len(self.buf) - TERM_BUF_LIMIT
                    del self.buf[:cut]
                    self.base += cut
            low = data.lower()
            if b"permission denied" in low or b"authentication failed" in low:
                self.auth_failed = True
            if not self.authed and self.prompts < 3 and b"assword" in low:
                self.prompts += 1
                time.sleep(0.05)
                try:
                    os.write(self.fd, (self._pw + "\n").encode())
                except OSError:
                    break
            elif self.prompts == 1 and not self.authed and self.proc_alive():
                self.authed = True
        self.alive = False
        self.closed = True


def term_open(user, password, cols=100, rows=30):
    user = (user or "").strip()
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", user):
        raise ValueError("账号不合法")
    if not password:
        raise ValueError("请输入系统密码")
    with TERM_LOCK:
        for sid, sess in list(TERM_SESSIONS.items()):
            if not sess.alive:
                TERM_SESSIONS.pop(sid, None)
        if len(TERM_SESSIONS) >= TERM_MAX_SESSIONS:
            # 到上限时先回收“60 秒无交互”的僵尸会话（页面刷新 / 断网留下的）
            stale = [x for x in TERM_SESSIONS.values() if time.time() - x.last > 60]
            stale.sort(key=lambda x: x.last)
            for x in stale[:max(1, len(TERM_SESSIONS) - TERM_MAX_SESSIONS + 1)]:
                TERM_SESSIONS.pop(x.id, None)
                x.kill()
                log_line("SSH", "term evict sid=%s idle=%ds" % (x.id[:8], int(time.time() - x.last)))
        if len(TERM_SESSIONS) >= TERM_MAX_SESSIONS:
            raise ValueError("已打开的终端太多（上限 %d），先关掉一个" % TERM_MAX_SESSIONS)
    sid = secrets.token_hex(8)
    sess = TermSession(sid, user, password, cols, rows)
    # 等握手：出现第二次口令提示 = 密码错；进程退出 = 连不上
    deadline = time.time() + 15
    while time.time() < deadline:
        time.sleep(0.15)
        if sess.auth_failed or sess.prompts >= 2:
            sess.kill()
            raise ValueError("账号或密码不正确")
        if not sess.alive or not sess.proc_alive():
            sess.kill()
            raise ValueError("登录失败（账号密码错误或 ssh 不可用）")
        if sess.prompts == 1:
            time.sleep(1.2)
            break
    if not sess.alive or not sess.proc_alive():
        sess.kill()
        raise ValueError("登录失败")
    sess.authed = True
    with TERM_LOCK:
        TERM_SESSIONS[sid] = sess
    log_line("SSH", "term open sid=%s user=%s" % (sid[:8], user))
    return sess


def term_get(sid):
    with TERM_LOCK:
        sess = TERM_SESSIONS.get(sid)
    if not sess or not sess.alive:
        raise ValueError("终端已断开，请重新连接")
    sess.last = time.time()
    return sess


def term_close(sid):
    with TERM_LOCK:
        sess = TERM_SESSIONS.pop(sid, None)
    if sess:
        sess.kill()


def term_close_all():
    with TERM_LOCK:
        sessions = list(TERM_SESSIONS.values())
        TERM_SESSIONS.clear()
    for sess in sessions:
        sess.kill()


def start_term_sweeper():
    def _loop():
        while True:
            time.sleep(30)
            now = time.time()
            with TERM_LOCK:
                dead = [s for s in TERM_SESSIONS.values()
                        if (not s.alive) or (now - s.last > TERM_IDLE_SECONDS)]
                for s in dead:
                    TERM_SESSIONS.pop(s.id, None)
            for s in dead:
                s.kill()
                log_line("SSH", "term reap sid=%s idle=%ds" % (s.id[:8], int(now - s.last)))

    t = threading.Thread(target=_loop, name="term-sweeper", daemon=True)
    t.start()
    return t


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "NASPanel/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A003
        pass

    # -- 基础响应 ------------------------------------------------------
    def _send(self, status, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, val in (extra or {}).items():
            self.send_header(key, val)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _err(self, status, message):
        self._send(status, {"ok": False, "error": message})

    def _client_ip(self):
        return self.client_address[0]

    def _cookie_token(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("naspanel="):
                return part.split("=", 1)[1]
        return ""

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def _guard(self, need_session=True, need_csrf=True):
        ip = self._client_ip()
        if not ip_allowed(ip, self.server.cfg["allow_cidrs"]):
            self._err(403, "来源地址不在允许范围：%s" % ip)
            return False
        if need_session and not session_valid(self._cookie_token(), ip):
            self._err(401, "未登录或会话过期")
            return False
        if need_csrf and self.command == "POST":
            if self.headers.get("X-Requested-With") != "nas-panel":
                self._err(403, "缺少请求标记")
                return False
        return True

    def _check_password(self, password):
        if not password:
            return False
        return verify_password(str(password), self.server.cfg["password_hash"])

    # -- 路由 ----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._serve_index()
        if path.startswith("/assets/"):
            return self._serve_asset(path)
        if path == "/api/ping":
            return self._send(200, {"ok": True, "ts": now_iso()})
        if path.startswith("/api/"):
            if not self._guard():
                return
            if path == "/api/state":
                try:
                    return self._send(200, {"ok": True, "data": build_state()})
                except Exception as exc:  # noqa: BLE001
                    log_line("ERROR", "state: %r" % (exc,))
                    return self._err(500, "状态采集失败：%s" % exc)
            if path == "/api/hp/test":
                return self._send(200, {"ok": True, "data": hp_test(force=True)})
            if path == "/api/hp/config":
                return self._send(200, {"ok": True, "data": hp_snapshot(force=True)})
            if path == "/api/res":
                return self._send(200, {"ok": True, "data": res_snapshot()})
            if path == "/api/disk":
                return self._send(200, {"ok": True, "data": disk_snapshot(force="1" in (self.path or ""))})
            if path == "/api/disk/cleanable":
                return self._send(200, {"ok": True, "data": clean_preview(force="1" in (self.path or ""))})
            if path == "/api/ssh/term/read":
                q = urllib.parse.parse_qs((self.path or "").split("?", 1)[1] if "?" in (self.path or "") else "")
                sid = (q.get("id") or [""])[0]
                try:
                    off = int((q.get("off") or ["0"])[0] or 0)
                except ValueError:
                    off = 0
                try:
                    sess = term_get(sid)
                except ValueError as exc:
                    return self._err(410, str(exc))
                chunk, newoff = sess.read(off)
                return self._send(200, {"ok": True, "data": {
                    "off": newoff,
                    "b64": base64.b64encode(chunk).decode("ascii"),
                    "closed": (not sess.alive)}})
            if path == "/api/disk/drill":
                q = urllib.parse.parse_qs((self.path or "").split("?", 1)[1] if "?" in (self.path or "") else "")
                target = (q.get("path") or [""])[0]
                if not target:
                    return self._err(400, "缺少 path 参数")
                try:
                    return self._send(200, {"ok": True, "data": disk_drill(
                        target, force="1" in (self.path or ""))})
                except ValueError as exc:
                    return self._err(400, str(exc))
            return self._err(404, "未知接口")
        return self._err(404, "not found")

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/api/login":
            return self._login()
        if not self._guard():
            return
        # 终端输入/改尺寸是高频小请求（一次按键一条），逐键算「操作」会把正常打字限流
        if path not in ("/api/ssh/term/write", "/api/ssh/term/resize"):
            if not action_rate_ok(self._client_ip()):
                return self._err(429, "操作过于频繁，请稍后再试")
        body = self._read_json()
        if path == "/api/logout":
            drop_session(self._cookie_token())
            ssh_close_all()
            term_close_all()
            return self._send(200, {"ok": True}, extra={
                "Set-Cookie": "naspanel=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if path == "/api/action":
            return self._action(body)
        if path == "/api/hp/toggle":
            return self._hp_toggle(body)
        if path == "/api/hp/subscribe":
            return self._hp_subscribe(body)
        if path == "/api/hp/node":
            return self._hp_node(body)
        if path == "/api/disk/clean":
            return self._disk_clean(body)
        if path == "/api/ssh/open":
            return self._ssh_open(body)
        if path == "/api/ssh/run":
            return self._ssh_run(body)
        if path == "/api/ssh/close":
            return self._ssh_close(body)
        if path == "/api/ssh/term/open":
            return self._term_open(body)
        if path == "/api/ssh/term/write":
            return self._term_write(body)
        if path == "/api/ssh/term/resize":
            return self._term_resize(body)
        if path == "/api/ssh/term/close":
            return self._term_close(body)
        return self._err(404, "未知接口")

    # -- 具体动作 ------------------------------------------------------
    def _login(self):
        ip = self._client_ip()
        if not ip_allowed(ip, self.server.cfg["allow_cidrs"]):
            return self._err(403, "来源地址不在允许范围：%s" % ip)
        if login_locked(ip):
            return self._err(429, "密码错误次数过多，请 5 分钟后再试")
        body = self._read_json()
        if not self._check_password(body.get("password")):
            login_failed(ip)
            log_line("LOGIN", "fail ip=%s" % ip)
            return self._err(403, "密码错误")
        token = new_session(ip)
        log_line("LOGIN", "ok ip=%s" % ip)
        self._send(200, {"ok": True}, extra={
            "Set-Cookie": "naspanel=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict"
                          % (token, SESSION_HOURS * 3600)})

    def _disk_clean(self, body):
        ip = self._client_ip()
        if not self._check_password(body.get("password")):
            log_line("AUTH", "clean denied ip=%s" % ip)
            return self._err(403, "管理员密码错误")
        if not os.path.exists(CLEAN_SCRIPT):
            return self._err(500, "清理脚本不存在：%s" % CLEAN_SCRIPT)
        log_line("CLEAN", "start ip=%s" % ip)
        try:
            rows, total = _run_clean("--apply")
        except Exception as exc:  # noqa: BLE001
            log_line("CLEAN", "failed %r" % (exc,))
            return self._err(500, "清理失败：%s" % exc)
        with CLEAN_LOCK:
            CLEAN_CACHE.update(ts=0.0, rows=[], total=0)
        log_line("CLEAN", "done freed=%d bytes" % total)
        return self._send(200, {"ok": True, "data": dict(rows=rows, total=total)})

    def _ssh_open(self, body):
        ip = self._client_ip()
        user = str(body.get("user") or "").strip()
        key = "ssh:" + ip
        if login_locked(key):
            return self._err(429, "SSH 密码错误次数过多，请 5 分钟后再试")
        # 凭据是「系统账号 + 系统密码」，由 ssh 本身校验；
        # 这里不再要求面板管理员密码（避免一次操作连输两遍密码）
        try:
            sess = ssh_open(user, body.get("ssh_password"))
        except ValueError as exc:
            login_failed(key)
            log_line("SSH", "open fail user=%s ip=%s: %s" % (user, ip, exc))
            return self._err(401, str(exc))
        return self._send(200, {"ok": True, "data": dict(
            id=sess.id, user=sess.user, host=SSH_PEER, opened=sess.opened,
            max_sessions=SSH_MAX_SESSIONS, idle_minutes=int(SSH_IDLE_SECONDS // 60))})

    def _ssh_run(self, body):
        try:
            data = ssh_run(body.get("id"), body.get("cmd"))
        except ValueError as exc:
            return self._err(400, str(exc))
        return self._send(200, {"ok": True, "data": data})

    def _ssh_close(self, body):
        ssh_close(body.get("id"))
        return self._send(200, {"ok": True})

    def _action(self, body):
        ip = self._client_ip()
        if not self._check_password(body.get("password")):
            log_line("AUTH", "action denied ip=%s" % ip)
            return self._err(403, "管理员密码错误")
        kind = body.get("kind")
        ident = str(body.get("id") or "")
        action = str(body.get("action") or "")
        if action not in ("start", "stop", "restart"):
            return self._err(400, "只允许 start / stop / restart")
        if kind == "systemd":
            meta = SERVICE_BY_ID.get(ident)
            if not meta or meta["kind"] != "systemd":
                return self._err(404, "未知服务")
            rc, out, err = run(["systemctl", action, meta["unit"]], timeout=90.0)
            output = (out + err).strip()[-800:]
            log_line("ACTION", "systemd %s %s rc=%d ip=%s" % (action, meta["unit"], rc, ip))
        elif kind == "docker":
            rows, _ = docker_snapshot()
            names = {r["name"] for r in rows}
            if ident not in names:
                return self._err(404, "容器不存在")
            rc2, out2, _ = run(["docker", "inspect", "--format", "{{.HostConfig.AutoRemove}}", ident], timeout=10.0)
            if rc2 == 0 and out2.strip() == "true":
                return self._err(403, "该容器以 --rm 运行，停止/重启会导致容器被删除，已拒绝")
            rc, out, err = run(["docker", action, ident], timeout=120.0)
            output = (out + err).strip()[-800:]
            if rc == 0:
                if action == "stop":
                    record_stop(ident, True)
                elif action == "start":
                    record_stop(ident, False)
            log_line("ACTION", "docker %s %s rc=%d ip=%s" % (action, ident, rc, ip))
        else:
            return self._err(400, "未知类型")
        time.sleep(0.6)
        invalidate_state()
        return self._send(200, {"ok": rc == 0, "rc": rc, "output": output,
                                "message": "已执行：%s %s" % (action, ident)})

    def _hp_toggle(self, body):
        if not self._check_password(body.get("password")):
            return self._err(403, "管理员密码错误")
        enable = bool(body.get("enable"))
        res = hp_toggle(enable)
        log_line("PROXY", "%s rc=%d" % ("start" if enable else "stop", res["rc"]))
        invalidate_state()
        return self._send(200, {"ok": True, "data": res,
                                "message": "代理已%s" % ("启动" if enable else "关闭")})

    def _hp_subscribe(self, body):
        if not self._check_password(body.get("password")):
            return self._err(403, "管理员密码错误")
        url = str(body.get("url") or "").strip()
        if not re.match(r"^(https?)://[^\s]{6,600}$", url):
            return self._err(400, "订阅链接格式不对（需要 http(s):// 开头）")
        log_line("PROXY", "subscribe %s" % url[:60])
        res = hp_set_subscription(url)
        invalidate_state()
        return self._send(200, {"ok": res.get("ok", False), "data": res,
                                "message": res.get("fixed") or "订阅已更新"})

    def _hp_node(self, body):
        if not self._check_password(body.get("password")):
            return self._err(403, "管理员密码错误")
        node_id = str(body.get("id") or "")
        cfg, _ = hp_config()
        if not cfg or node_id not in cfg["nodes"]:
            return self._err(400, "节点不存在")
        res = hp_set_node(node_id)
        log_line("PROXY", "set node %s" % node_id[:8])
        invalidate_state()
        return self._send(200, {"ok": res.get("ok", False), "data": res,
                                "message": "主节点已切换"})

    # -- 真 TTY 终端 ---------------------------------------------------
    def _term_open(self, body):
        ip = self._client_ip()
        key = "term:" + ip
        if login_locked(key):
            return self._err(429, "SSH 密码错误次数过多，请 5 分钟后再试")
        user = str(body.get("user") or "root").strip()
        pw = str(body.get("ssh_password") or "")
        try:
            cols = int(body.get("cols") or 100)
            rows = int(body.get("rows") or 30)
        except (TypeError, ValueError):
            cols, rows = 100, 30
        try:
            sess = term_open(user, pw, cols, rows)
        except ValueError as exc:
            if "不正确" in str(exc) or "失败" in str(exc):
                login_failed(key)
            log_line("SSH", "term open failed user=%s: %s" % (user, exc))
            return self._err(401, str(exc))
        return self._send(200, {"ok": True, "data": {
            "id": sess.id, "user": sess.user, "cols": sess.cols, "rows": sess.rows,
            "opened": sess.opened, "max_sessions": TERM_MAX_SESSIONS,
            "idle_minutes": int(TERM_IDLE_SECONDS // 60)}})

    def _term_write(self, body):
        try:
            sess = term_get(str(body.get("id") or ""))
        except ValueError as exc:
            return self._err(410, str(exc))
        raw = base64.b64decode(str(body.get("b64") or ""), validate=False)
        if len(raw) > 8192:
            return self._err(413, "单次输入过大")
        sess.write(raw)
        return self._send(200, {"ok": True})

    def _term_resize(self, body):
        try:
            sess = term_get(str(body.get("id") or ""))
        except ValueError as exc:
            return self._err(410, str(exc))
        try:
            cols = int(body.get("cols") or sess.cols)
            rows = int(body.get("rows") or sess.rows)
        except (TypeError, ValueError):
            return self._err(400, "尺寸不合法")
        sess.resize(cols, rows)
        return self._send(200, {"ok": True})

    def _term_close(self, body):
        sid = str(body.get("id") or "")
        term_close(sid)
        return self._send(200, {"ok": True})

    def _serve_asset(self, path):
        name = path[len("/assets/"):]
        if "/" in name or name.startswith("."):
            return self._err(404, "not found")
        full = os.path.join(ASSETS_DIR, name)
        if not os.path.isfile(full):
            return self._err(404, "not found")
        ctype = "application/octet-stream"
        if name.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif name.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        try:
            with open(full, "rb") as fh:
                body = fh.read()
        except OSError as exc:
            return self._err(500, "读取资源失败：%s" % exc)
        return self._send(200, body, ctype, extra={"Cache-Control": "public, max-age=86400"})

    def _serve_index(self):
        try:
            with open(INDEX_PATH, "rb") as fh:
                body = fh.read()
        except Exception as exc:  # noqa: BLE001
            return self._err(500, "缺少 index.html：%s" % exc)
        self._send(200, body, "text/html; charset=utf-8")


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # 默认 backlog 只有 5：浏览器一次页面加载会并发 6+ 条连接，
    # 排队一满内核就丢 SYN（TcpExtListenOverflows），表现为“页面没反应”。
    request_queue_size = 128


# --------------------------------------------------------------------------
# 配置 / 入口
# --------------------------------------------------------------------------

DEFAULT_CONF = dict(
    bind="0.0.0.0",
    port=8899,
    password_hash="",
    allow_cidrs=["127.0.0.1/32", "192.168.10.0/24", "192.168.66.0/24"],
)


def load_conf(create=False, password=None):
    if os.path.exists(CONF_PATH):
        with open(CONF_PATH, "r", encoding="utf-8") as fh:
            conf = json.load(fh)
        for key, val in DEFAULT_CONF.items():
            conf.setdefault(key, val)
        return conf, False
    if not create:
        raise SystemExit("配置不存在，请先运行：%s --init" % sys.argv[0])
    pwd = password or secrets.token_urlsafe(12)
    conf = dict(DEFAULT_CONF)
    conf["password_hash"] = hash_password(pwd)
    with open(CONF_PATH, "w", encoding="utf-8") as fh:
        json.dump(conf, fh, indent=2, ensure_ascii=False)
    os.chmod(CONF_PATH, 0o600)
    print("已生成配置：%s" % CONF_PATH)
    print("初始管理员密码：%s" % pwd)
    print("（可用 --set-password 修改）")
    return conf, True


def set_password(password):
    conf, _ = load_conf(create=True)
    conf["password_hash"] = hash_password(password)
    with open(CONF_PATH, "w", encoding="utf-8") as fh:
        json.dump(conf, fh, indent=2, ensure_ascii=False)
    os.chmod(CONF_PATH, 0o600)
    print("密码已更新")


HIST_LOCK = threading.Lock()


def hist_load():
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return data
    except Exception:  # noqa: BLE001
        pass
    return []


def hist_append(sample):
    """追加一条样本并落盘（原子替换），超过 HIST_KEEP 丢最老的。"""
    with HIST_LOCK:
        data = hist_load()
        data.append(sample)
        if len(data) > HIST_KEEP:
            data = data[-HIST_KEEP:]
        try:
            tmp = HISTORY_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, separators=(",", ":"))
            os.replace(tmp, HISTORY_PATH)
        except Exception:  # noqa: BLE001
            pass
    return len(data)


def hist_series(hours=24.0, buckets=HIST_BUCKETS):
    """把样本按时间分桶，返回每条曲线（cpu/mem/swap/disk）的桶均值序列。"""
    now = time.time()
    start = now - hours * 3600.0
    width = (hours * 3600.0) / buckets
    series = dict(cpu=[None] * buckets, mem=[None] * buckets,
                  swap=[None] * buckets, disk=[None] * buckets)
    acc = dict((k, [[] for _ in range(buckets)]) for k in series)
    count = 0
    with HIST_LOCK:
        data = hist_load()
    for item in data:
        try:
            ts = float(item.get("ts", 0))
        except Exception:  # noqa: BLE001
            continue
        if ts < start or ts > now + 60:
            continue
        idx = int((ts - start) / width)
        if idx < 0 or idx >= buckets:
            continue
        count += 1
        for key in acc:
            val = item.get(key)
            if val is not None:
                try:
                    acc[key][idx].append(float(val))
                except Exception:  # noqa: BLE001
                    pass
    # 刚部署时数据只有几分钟，分桶后整条线可能只剩 1 个点，
    # 这种情况直接返回原始样本（最多 60 个），让曲线一开始就能看
    recent = [x for x in data if start <= float(x.get("ts", 0) or 0) <= now + 60]
    if len(recent) >= 2:
        span = float(recent[-1]["ts"]) - float(recent[0]["ts"])
        if span < 7200.0:
            raw = recent[-60:]
            out = {}
            for key in ("cpu", "mem", "swap", "disk"):
                out[key] = [x.get(key) for x in raw]
            out["span_hours"] = round(span / 3600.0, 3)
            out["buckets"] = len(raw)
            out["samples"] = len(raw)
            out["last_ts"] = raw[-1].get("ts")
            out["mode"] = "raw"
            return out

    for key, lists in acc.items():
        series[key] = [round(sum(v) / len(v), 1) if v else None for v in lists]
    out = dict(series)
    out["span_hours"] = hours
    out["buckets"] = buckets
    out["samples"] = count
    out["last_ts"] = data[-1].get("ts") if data else None
    out["mode"] = "bucket"
    return out


# ---------------------------------------------------------------- 24 小时访问 / 流量
# 认证网关写的访问日志目录（JSONL，一天一个文件），按你的部署改这里
ACCESS_DIR = os.environ.get("PANEL_ACCESS_DIR", "/var/log/gateway-access")
ACCESS_STATE_PATH = os.path.join(BASE_DIR, "access-agg.json")
NETIO_STATE_PATH = os.path.join(BASE_DIR, "netio.json")
ACCESS_INTERVAL = 60.0
NETIO_INTERVAL = 120.0
TRAF_BUCKETS = 24
TRAF_KEEP_HOURS = 27
TRAF_LOCK = threading.Lock()

# 认证门日志里的服务名 → 容器名；没映射到的按原名统计
SVC2CT = {
    "nas 入口": "nas-proxy",
    "媒体库": "jellyfin",
    "下载器": "qbittorrent",
    "私有网盘": "nextcloud",
    "照片备份": "immich-server",
    "文件同步": "syncthing",
    "智能家居": "homeassistant",
    "portainer": "portainer",
}
# 已下线/不再提供服务的入口，统计里直接丢弃
SVC_DROP = set()
# 只保留面向用户的容器（数据库/缓存/临时任务的内部流量不算业务流量）
CT_KEEP = {
    # 只算应用容器：入口 nginx / 网关容器会把同一段流量重复计一次，故排除
    "jellyfin", "qbittorrent", "nextcloud", "immich-server",
    "syncthing", "homeassistant", "portainer",
}
CT_LABEL = {
    "jellyfin": "媒体库",
    "qbittorrent": "下载器",
    "nextcloud": "私有网盘",
    "immich-server": "照片备份",
    "syncthing": "文件同步",
    "homeassistant": "智能家居",
    "portainer": "容器管理",
}

ACC = {"off": {}, "hour": {}}
NETIO = {"prev": {}, "hour": {}}
# 最近一次网卡采样算出的“实时速率”（字节/秒，含收发），供拓扑图做活动呼吸效果
LIVE = {"ts": 0.0, "rate": {}}
_NETIO_LAST = {"ts": 0.0}
_SIZE_UNITS = {
    "b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
    "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4,
}


def _hour_key(ts):
    return str(int(float(ts) // 3600) * 3600)


def _parse_bytes(txt):
    txt = str(txt).strip()
    if not txt:
        return 0
    num = "".join(ch for ch in txt if ch.isdigit() or ch == ".")
    unit = "".join(ch for ch in txt if ch.isalpha()).lower()
    try:
        return int(float(num) * _SIZE_UNITS.get(unit, 1))
    except Exception:  # noqa: BLE001
        return 0


def _traf_load():
    try:
        with open(ACCESS_STATE_PATH, "r", encoding="utf-8") as f:
            d = json.load(f) or {}
        ACC["off"] = d.get("off") or {}
        ACC["hour"] = d.get("hour") or {}
    except Exception:  # noqa: BLE001
        pass
    try:
        with open(NETIO_STATE_PATH, "r", encoding="utf-8") as f:
            d = json.load(f) or {}
        NETIO["prev"] = d.get("prev") or {}
        NETIO["hour"] = d.get("hour") or {}
    except Exception:  # noqa: BLE001
        pass


def _traf_save():
    cut = str(int((time.time() - TRAF_KEEP_HOURS * 3600) // 3600) * 3600)
    for store in (ACC["hour"], NETIO["hour"]):
        for k in [k for k in list(store.keys()) if k < cut]:
            store.pop(k, None)
    try:
        tmp = ACCESS_STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"off": ACC["off"], "hour": ACC["hour"]}, f)
        os.replace(tmp, ACCESS_STATE_PATH)
    except Exception as exc:  # noqa: BLE001
        log_line("TRAF", "access 落盘失败：%s" % exc)
    try:
        tmp = NETIO_STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"prev": NETIO["prev"], "hour": NETIO["hour"]}, f)
        os.replace(tmp, NETIO_STATE_PATH)
    except Exception as exc:  # noqa: BLE001
        log_line("TRAF", "netio 落盘失败：%s" % exc)


def _access_scan():
    """增量扫描 access-YYYY-MM-DD.jsonl，按小时累计每个服务的请求数与错误数。"""
    now = time.time()
    since = now - TRAF_KEEP_HOURS * 3600
    days = {time.strftime("%Y-%m-%d", time.localtime(now - 0)),
            time.strftime("%Y-%m-%d", time.localtime(now - 86400))}
    for day in sorted(days):
        path = os.path.join(ACCESS_DIR, "access-%s.jsonl" % day)
        try:
            st = os.stat(path)
        except Exception:  # noqa: BLE001
            continue
        ino, off = (ACC["off"].get(path) or [0, 0])[:2]
        if ino != st.st_ino or off > st.st_size:
            off = 0
        if off >= st.st_size:
            ACC["off"][path] = [st.st_ino, off]
            continue
        try:
            with open(path, "rb") as f:
                f.seek(off)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    off += len(line)
                    if len(line) < 8:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:  # noqa: BLE001
                        continue
                    try:
                        t = datetime.strptime(
                            str(rec.get("ts") or "")[:19], "%Y-%m-%dT%H:%M:%S"
                        ).replace(tzinfo=timezone.utc).timestamp()
                    except Exception:  # noqa: BLE001
                        continue
                    if t < since or t > now + 300:
                        continue
                    svc = str(rec.get("svc") or "").strip()
                    if not svc or svc in SVC_DROP or svc.lower() in SVC_DROP:
                        continue
                    ct = SVC2CT.get(svc.lower()) or SVC2CT.get(svc) or svc
                    row = ACC["hour"].setdefault(_hour_key(t), {}).setdefault(ct, [0, 0])
                    row[0] += 1
                    try:
                        # 只把 5xx 计为错误：认证门的 401/403 是未授权探测，不算服务异常
                        if int(rec.get("status") or 0) >= 500:
                            row[1] += 1
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001
            log_line("TRAF", "读 %s 失败：%s" % (path, exc))
            continue
        ACC["off"][path] = [st.st_ino, off]


def _netio_scan():
    """取各容器网卡累计收发字节（/proc/<pid>/net/dev，精确到字节），做差累加到当前小时。

    不用 docker stats 的 NetIO：那个值按 3 位有效数字取整，慢增长时差值会跳成整 MB。
    """
    rc, out, err = run(["docker", "ps", "-q"], timeout=20.0)
    if rc != 0 or not out.strip():
        if err:
            log_line("TRAF", "docker ps 失败：%s" % err.strip()[:120])
        return
    ids = [x.strip() for x in out.split() if x.strip()]
    rc2, out2, _ = run(
        ["docker", "inspect", "--format", "{{.Name}}|{{.State.Pid}}"] + ids,
        timeout=25.0,
    )
    if rc2 != 0:
        return
    cur = {}
    for line in out2.splitlines():
        if "|" not in line:
            continue
        name, pid = line.rsplit("|", 1)
        name = name.strip().lstrip("/")
        try:
            pid = int(pid.strip())
        except Exception:  # noqa: BLE001
            continue
        if pid <= 0:
            continue
        rx = tx = 0
        try:
            with open("/proc/%d/net/dev" % pid, "r", encoding="utf-8") as f:
                for ln in f.readlines()[2:]:
                    if ":" not in ln:
                        continue
                    iface, data = ln.split(":", 1)
                    if iface.strip() == "lo":
                        continue
                    cols = data.split()
                    if len(cols) < 9:
                        continue
                    rx += int(cols[0])
                    tx += int(cols[8])
        except Exception:  # noqa: BLE001
            continue
        cur[name] = [rx, tx]
    if not cur:
        return
    now = time.time()
    dt = (now - _NETIO_LAST["ts"]) if _NETIO_LAST["ts"] else 0.0
    hk = _hour_key(now)
    prev = NETIO["prev"]
    delta = {}
    for name, val in cur.items():
        p = prev.get(name)
        dx = dy = 0
        if p and val[0] >= p[0] and val[1] >= p[1]:
            dx, dy = val[0] - p[0], val[1] - p[1]
        if dx or dy:
            row = NETIO["hour"].setdefault(hk, {}).setdefault(name, [0, 0])
            row[0] += dx
            row[1] += dy
        delta[name] = dx + dy
    NETIO["prev"] = cur
    # 速率只在两次采样间隔合理时才算（重启后第一次没有 dt）
    if dt >= 20.0:
        LIVE["ts"] = round(now, 1)
        LIVE["rate"] = {k: round(v / dt, 1) for k, v in delta.items() if v > 0}
    _NETIO_LAST["ts"] = now


def traffic_state():
    """近 24 小时按小时聚合：每个服务的请求数、错误数、流量，供前端画趋势。"""
    now = time.time()
    base = int(now // 3600) * 3600
    hours = [base - (TRAF_BUCKETS - 1 - i) * 3600 for i in range(TRAF_BUCKETS)]
    with TRAF_LOCK:
        acc = {k: dict(v) for k, v in ACC["hour"].items()}
        net = {k: dict(v) for k, v in NETIO["hour"].items()}
    agg = {}
    for i, hk in enumerate(hours):
        k = str(int(hk))
        for ct, val in (acc.get(k) or {}).items():
            r = agg.setdefault(ct, {"req": [0] * TRAF_BUCKETS,
                                    "err": [0] * TRAF_BUCKETS,
                                    "bytes": [0] * TRAF_BUCKETS})
            r["req"][i] += int(val[0])
            r["err"][i] += int(val[1])
        for ct, val in (net.get(k) or {}).items():
            if ct not in CT_KEEP:
                continue
            r = agg.setdefault(ct, {"req": [0] * TRAF_BUCKETS,
                                    "err": [0] * TRAF_BUCKETS,
                                    "bytes": [0] * TRAF_BUCKETS})
            r["bytes"][i] += int(val[0]) + int(val[1])
    rows = []
    for ct, r in agg.items():
        req, bts, errs = sum(r["req"]), sum(r["bytes"]), sum(r["err"])
        if not req and not bts:
            continue
        rows.append(dict(name=CT_LABEL.get(ct, ct), key=ct, req=req, err=errs, bytes=bts,
                         series=r["bytes"], req_series=r["req"]))
    rows.sort(key=lambda x: (x["bytes"], x["req"]), reverse=True)
    return dict(
        ts=now_iso(),
        hours=TRAF_BUCKETS,
        rows=rows[:10],
        total_req=sum(x["req"] for x in rows),
        total_bytes=sum(x["bytes"] for x in rows),
        total_err=sum(x["err"] for x in rows),
        warm=bool(ACC["off"]),
        live=dict(LIVE.get("rate") or {}),
        live_ts=LIVE.get("ts") or 0,
    )


def start_traffic_sampler():
    """后台线程：访问日志 60s 增量一次、容器流量 120s 一次，落盘供重启恢复。"""

    def loop():
        time.sleep(3)
        _traf_load()
        with TRAF_LOCK:
            _access_scan()
        _netio_scan()
        _traf_save()
        n = 0
        while True:
            time.sleep(ACCESS_INTERVAL)
            try:
                with TRAF_LOCK:
                    _access_scan()
                n += 1
                _netio_scan()
                _traf_save()
            except Exception as exc:  # noqa: BLE001
                log_line("TRAF", "采样失败：%s" % exc)

    t = threading.Thread(target=loop, name="traffic-sampler", daemon=True)
    t.start()
    return t


def hist_sample_once():
    try:
        h = host_info()
        sample = dict(
            ts=round(time.time(), 1),
            cpu=(h.get("cpu") or {}).get("pct"),
            mem=(h.get("mem") or {}).get("pct"),
            swap=(h.get("swap") or {}).get("pct"),
            disk=(h.get("disk") or {}).get("pct"),
        )
        hist_append(sample)
        return sample
    except Exception as exc:  # noqa: BLE001
        log_line("HIST", "采样失败：%s" % exc)
        return None


def start_history_sampler():
    """后台每 2 分钟采一次 CPU/内存/Swap/磁盘，供概览页画 24 小时趋势。"""

    def loop():
        # 启动初期加密采样（30 秒），攒够 24 个点后转常规 2 分钟节奏，
        # 这样刚部署完不用等两小时就能看到曲线
        time.sleep(8)
        while True:
            hist_sample_once()
            try:
                n = len(hist_load())
            except Exception:  # noqa: BLE001
                n = 0
            time.sleep(30.0 if n < 24 else HIST_INTERVAL)

    th = threading.Thread(target=loop, name="history-sampler", daemon=True)
    th.start()
    return th


def start_proxy_prober(interval=300.0, first_delay=25.0):
    """后台每 5 分钟跑一次三站点探测，让概览页的“代理连通性”始终有近期结果。

    /api/state 只读缓存（不能阻塞首屏），所以缓存得靠这个线程保持新鲜。
    """

    def loop():
        time.sleep(first_delay)
        while True:
            try:
                hp_test(force=True)
            except Exception as exc:  # noqa: BLE001
                log_line("PROBE", "后台探测失败：%s" % exc)
            time.sleep(interval)

    th = threading.Thread(target=loop, name="proxy-prober", daemon=True)
    th.start()
    return th


# ===================== 资源详情（CPU / 内存 / Swap） =====================
RES_LOCK = threading.Lock()
RES_STATE = {"ts": 0.0, "procs": 0, "top_cpu": [], "top_mem": [], "top_swap": []}
_PROC_PREV = {}
_NCPU = os.cpu_count() or 4
_UID_CACHE = {}


def _user_of(uid):
    if uid in _UID_CACHE:
        return _UID_CACHE[uid]
    try:
        import pwd
        name = pwd.getpwuid(uid).pw_name
    except Exception:  # noqa: BLE001
        name = str(uid)
    _UID_CACHE[uid] = name
    return name


def _stat_total():
    try:
        with open("/proc/stat", "r") as fh:
            parts = fh.readline().split()
        return sum(int(x) for x in parts[1:] if x.isdigit())
    except Exception:  # noqa: BLE001
        return 0


_CT_MAP = {"ts": 0.0, "by_id": {}}


def _container_map():
    if _CT_MAP["by_id"] and (time.time() - _CT_MAP["ts"]) < 60:
        return _CT_MAP["by_id"]
    mapping = {}
    try:
        rc, out, _ = run(["docker", "ps", "--format", "{{.ID}}|{{.Names}}"], timeout=10)
        if rc == 0:
            for line in out.strip().splitlines():
                if "|" in line:
                    cid, cname = line.split("|", 1)
                    mapping[cid.strip()] = cname.strip()
    except Exception:  # noqa: BLE001
        pass
    _CT_MAP.update(ts=time.time(), by_id=mapping)
    return mapping


def _cmdline_of(pid):
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as fh:
            raw = fh.read(4096)
    except Exception:  # noqa: BLE001
        return ""
    if not raw:
        return ""
    parts = [x.decode("utf-8", "replace") for x in raw.split(b"\0") if x]
    if not parts:
        return ""
    head = os.path.basename(parts[0])
    extra = []
    for arg in parts[1:3]:
        if arg.startswith("-"):
            continue
        extra.append(os.path.basename(arg))
    txt = " ".join([head] + extra).strip()
    return txt[:60]


def _proc_one(pid):
    base = "/proc/" + pid
    try:
        with open(base + "/stat", "r") as fh:
            raw = fh.read()
    except Exception:  # noqa: BLE001
        return None
    lp = raw.find("(")
    rp = raw.rfind(")")
    if lp < 0 or rp < 0:
        return None
    name = raw[lp + 1:rp]
    fields = raw[rp + 2:].split()
    try:
        ticks = int(fields[11]) + int(fields[12])
        state = fields[0]
    except Exception:  # noqa: BLE001
        return None
    rss = swap = 0
    user = ""
    threads = 0
    try:
        with open(base + "/status", "r") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) * 1024
                elif line.startswith("VmSwap:"):
                    swap = int(line.split()[1]) * 1024
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
                elif line.startswith("Uid:"):
                    user = _user_of(int(line.split()[1]))
    except Exception:  # noqa: BLE001
        pass
    ct = ""
    try:
        with open(base + "/cgroup", "r") as fh:
            for line in fh:
                m = re.search(r"docker[-/]([0-9a-f]{12,64})", line)
                if m:
                    cid = m.group(1)[:12]
                    ct = _container_map().get(cid, "")
                    if not ct:
                        ct = "docker:" + cid
                    break
    except Exception:  # noqa: BLE001
        pass
    cmd = _cmdline_of(pid)
    return dict(pid=int(pid), name=name, state=state, ticks=ticks, rss=rss,
                swap=swap, user=user, threads=threads, cmd=cmd, ct=ct)


def res_sample_once():
    total = _stat_total()
    prev_total = RES_STATE.get("_total") or 0
    dtot = total - prev_total if prev_total else 0
    pids = [x for x in os.listdir("/proc") if x.isdigit()]
    rows = []
    prev = _PROC_PREV
    for pid in pids:
        info = _proc_one(pid)
        if info is None:
            continue
        old = prev.get(info["pid"])
        pct = 0.0
        if old is not None and dtot > 0:
            dt = info["ticks"] - old
            if dt > 0:
                pct = dt / float(dtot) * 100.0 * _NCPU
        info["cpu"] = round(pct, 1)
        rows.append(info)
    newprev = {r["pid"]: r["ticks"] for r in rows}
    _PROC_PREV.clear()
    _PROC_PREV.update(newprev)
    alive = [r for r in rows if r["state"] != "Z"]
    top_cpu = sorted(alive, key=lambda r: r["cpu"], reverse=True)[:12]
    top_mem = sorted([r for r in alive if r["rss"] > 0], key=lambda r: r["rss"], reverse=True)[:12]
    top_swap = sorted([r for r in alive if r["swap"] > 0], key=lambda r: r["swap"], reverse=True)[:12]
    def slim(lst):
        return [dict(pid=r["pid"], name=r["name"], user=r["user"], cpu=r["cpu"],
                     rss=r["rss"], swap=r["swap"], threads=r["threads"],
                     cmd=r.get("cmd") or "", ct=r.get("ct") or "") for r in lst]
    with RES_LOCK:
        RES_STATE.update(ts=round(time.time(), 1), procs=len(alive), _total=total,
                         top_cpu=slim(top_cpu), top_mem=slim(top_mem), top_swap=slim(top_swap))


def res_snapshot():
    with RES_LOCK:
        data = dict(RES_STATE)
    data.pop("_total", None)
    try:
        data["load"] = [round(x, 2) for x in os.getloadavg()]
    except Exception:  # noqa: BLE001
        data["load"] = []
    data["cores"] = _NCPU
    try:
        h = host_info()
        data["cpu_pct"] = (h.get("cpu") or {}).get("pct")
        data["mem"] = h.get("mem")
        data["swap"] = h.get("swap")
    except Exception:  # noqa: BLE001
        pass
    return data


def start_res_sampler():
    def loop():
        time.sleep(3)
        while True:
            try:
                res_sample_once()
            except Exception as exc:  # noqa: BLE001
                log_line("RES", "采样失败：%s" % exc)
            time.sleep(3.0)

    th = threading.Thread(target=loop, name="res-sampler", daemon=True)
    th.start()
    return th


# ===================== 磁盘占用 =====================
DISK_TARGETS = [
    ("/var/lib/docker", "Docker 镜像与容器层", ""),
    ("/srv/media", "媒体库", ""),
    ("/opt", "/opt 应用目录", ""),
    ("/var/log", "/var/log 日志", ""),
    ("/root/.cache", "root 缓存", ""),
    ("/var/cache/apt", "apt 包缓存", ""),
    ("/var/lib", "/var/lib 其他（不含 docker）", "/var/lib/docker"),
    ("/tmp", "/tmp 临时文件", ""),
]
CLEAN_SCRIPT = "/usr/local/sbin/nas-clean.sh"
DISK_LOCK = threading.Lock()
DISK_STATE = {"ts": 0.0, "dirs": [], "scanning": False, "df": {}, "docker": {}}
CLEAN_CACHE = {"ts": 0.0, "rows": [], "total": 0}
CLEAN_LOCK = threading.Lock()


def _du_bytes(path, exclude="", timeout=120):
    args = ["du", "-sb"]
    if exclude:
        args.append("--exclude=" + exclude)
    args.append(path)
    rc, out, _ = run(args, timeout=timeout)
    if rc != 0 or not out.strip():
        return 0
    try:
        return int(out.split()[0])
    except Exception:  # noqa: BLE001
        return 0


def disk_scan():
    with DISK_LOCK:
        if DISK_STATE.get("scanning"):
            return
        DISK_STATE["scanning"] = True
    try:
        dirs = []
        for path, label, exclude in DISK_TARGETS:
            if not os.path.isdir(path):
                continue
            dirs.append(dict(path=path, label=label, bytes=_du_bytes(path, exclude)))
        dirs.sort(key=lambda x: x["bytes"], reverse=True)
        df = {}
        try:
            total, used, free = shutil.disk_usage("/")
            df = dict(total=total, used=used, free=free,
                      pct=round(used * 100.0 / total, 1))
        except Exception:  # noqa: BLE001
            pass
        dk = {}
        rc, out, _ = run(["docker", "system", "df", "--format",
                          "{{.Type}}|{{.Size}}|{{.Reclaimable}}"], timeout=20)
        if rc == 0:
            for line in out.strip().splitlines():
                parts = line.split("|")
                if len(parts) == 3:
                    dk[parts[0]] = dict(size=parts[1].strip(), reclaim=parts[2].strip())
        with DISK_LOCK:
            DISK_STATE.update(ts=round(time.time(), 1), dirs=dirs, df=df, docker=dk)
    except Exception as exc:  # noqa: BLE001
        log_line("DISK", "扫描失败：%s" % exc)
    finally:
        with DISK_LOCK:
            DISK_STATE["scanning"] = False


def disk_snapshot(force=False):
    with DISK_LOCK:
        stale = (time.time() - (DISK_STATE.get("ts") or 0)) > 1800
        scanning = DISK_STATE.get("scanning")
        data = dict(DISK_STATE)
    if (force or stale) and not scanning:
        threading.Thread(target=disk_scan, name="disk-scan", daemon=True).start()
        scanning = True
    data["scanning"] = scanning
    return data


DRILL_ROOTS = ["/var/lib/docker", "/srv/media", "/opt", "/var/log",
               "/root/.cache", "/var/cache", "/var/lib", "/tmp", "/home", "/root"]
DRILL_DENY = {".ssh", ".gnupg", ".aws", ".kube", "credentials", "panel.conf.json"}
DRILL_CACHE = {}
DRILL_TTL = 300.0
DRILL_LOCK = threading.Lock()
DRILL_MAX = 24


def _drill_ok(path):
    """只允许在磁盘页列出的那些根目录内部逐层展开。"""
    try:
        rp = os.path.realpath(path)
    except Exception:  # noqa: BLE001
        return None
    if not rp.startswith("/") or not os.path.isdir(rp):
        return None
    parts = rp.strip("/").split("/")
    if any(seg in DRILL_DENY for seg in parts):
        return None
    for root in DRILL_ROOTS:
        if rp == root or rp.startswith(root + "/"):
            return rp
    return None


def disk_drill(path, force=False):
    rp = _drill_ok(path)
    if not rp:
        raise ValueError("路径不在允许范围内")
    now = time.time()
    with DRILL_LOCK:
        c = DRILL_CACHE.get(rp)
        if c and not force and now - c["ts"] < DRILL_TTL:
            return c["data"]
    rc, out, _ = run(["du", "-b", "--max-depth=1", rp], timeout=180)  # 注意：不能加 -s，否则只出总行
    total = 0
    rows = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            try:
                size = int(parts[0])
            except Exception:  # noqa: BLE001
                continue
            sp = parts[1]
            if sp == rp:
                total = size
                continue
            rows.append(dict(name=os.path.basename(sp), path=sp, bytes=size,
                             dir=os.path.isdir(sp)))
    rows.sort(key=lambda x: x["bytes"], reverse=True)
    if rows:
        total = sum(r["bytes"] for r in rows)  # du 的父行会把硬链接只算一次，用子项求和更自洽
    rest = rows[DRILL_MAX:]
    rows = rows[:DRILL_MAX]
    if rest:
        rows.append(dict(name="（其余 %d 项）" % len(rest), path="", bytes=sum(r["bytes"] for r in rest),
                         dir=False))
    data = dict(path=rp, total=total, rows=rows, ts=round(now, 1))
    with DRILL_LOCK:
        DRILL_CACHE[rp] = {"ts": now, "data": data}
    return data


def clean_preview(force=False):
    with CLEAN_LOCK:
        if not force and (time.time() - (CLEAN_CACHE.get("ts") or 0)) < 300:
            return dict(rows=list(CLEAN_CACHE["rows"]), total=CLEAN_CACHE["total"],
                        ts=CLEAN_CACHE["ts"], cached=True)
    rows, total = _run_clean("--dry-run")
    with CLEAN_LOCK:
        CLEAN_CACHE.update(ts=round(time.time(), 1), rows=rows, total=total)
    return dict(rows=rows, total=total, ts=CLEAN_CACHE["ts"], cached=False)


def _run_clean(mode):
    rc, out, err = run([CLEAN_SCRIPT, mode], timeout=600)
    rows = []
    total = 0
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 5:
            continue
        key, label, nbytes, status, note = parts[0], parts[1], parts[2], parts[3], parts[4]
        try:
            nb = int(nbytes)
        except Exception:  # noqa: BLE001
            nb = 0
        rows.append(dict(key=key, label=label, bytes=nb, status=status, note=note))
        if key != "TOTAL":
            total += nb
    if rc != 0 and not rows:
        log_line("CLEAN", "脚本失败 rc=%s err=%s" % (rc, err[:200]))
    return rows, total


def start_disk_sampler():
    def loop():
        time.sleep(60)
        while True:
            try:
                disk_scan()
            except Exception as exc:  # noqa: BLE001
                log_line("DISK", "定时扫描失败：%s" % exc)
            time.sleep(1800.0)

    th = threading.Thread(target=loop, name="disk-sampler", daemon=True)
    th.start()
    return th


def main(argv=None):
    parser = argparse.ArgumentParser(description="NAS 主机管理面板")
    parser.add_argument("--init", action="store_true", help="初始化配置并生成随机密码")
    parser.add_argument("--set-password", action="store_true", help="修改管理员密码")
    parser.add_argument("--password", default="", help="配合 --init/--set-password 指定密码")
    parser.add_argument("--port", type=int, default=0, help="监听端口（默认取配置）")
    parser.add_argument("--bind", default="", help="监听地址（默认取配置）")
    parser.add_argument("--check", action="store_true", help="打印一次状态快照后退出")
    parser.add_argument("--print-conf", action="store_true", help="打印配置摘要（不含密码哈希）")
    args = parser.parse_args(argv)

    if args.init:
        conf, created = load_conf(create=True, password=args.password or None)
        if not created:
            print("配置已存在：%s（如需改密码用 --set-password）" % CONF_PATH)
        return 0

    if args.set_password:
        pwd = args.password
        if not pwd:
            pwd = os.environ.get("PANEL_PASSWORD", "")
        if not pwd:
            pwd = getpass.getpass("新密码：")
        if len(pwd) < 6:
            print("密码太短（至少 6 位）")
            return 2
        set_password(pwd)
        return 0

    conf, _ = load_conf(create=False)

    if args.print_conf:
        print(json.dumps(dict(bind=conf["bind"], port=conf["port"],
                              allow_cidrs=conf["allow_cidrs"]), ensure_ascii=False, indent=2))
        return 0

    if args.check:
        state = build_state(force=True)
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return 0

    bind = args.bind or conf["bind"]
    port = args.port or conf["port"]
    server = PanelServer((bind, port), Handler)
    server.cfg = conf
    log_line("START", "listening %s:%s" % (bind, port))
    start_proxy_prober()
    start_history_sampler()
    start_traffic_sampler()
    start_ssh_sweeper()
    start_term_sweeper()
    start_res_sampler()
    start_disk_sampler()
    print("NAS 面板已启动：http://%s:%s/" % ("127.0.0.1" if bind == "0.0.0.0" else bind, port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

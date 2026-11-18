#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 demo 用的假数据（不包含任何真实主机信息）。"""
import json, os, random, datetime

random.seed(7)
now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

SERVICES = [
    ("docker", "容器引擎", "core", "systemd", "docker.service", "容器运行时（停掉等于所有容器停）", "停止后全部容器失联", "active（running）· enabled", "green"),
    ("ssh", "SSH 服务", "core", "systemd", "ssh.service", "远程维维护入口", "", "active（running）· enabled", "green"),
    ("cron", "定时任务", "core", "systemd", "cron.service", "计划任务调度", "", "active（running）· enabled", "green"),
    ("smb", "SMB 共享", "core", "systemd", "smbd.service", "局域网文件共享", "停掉后共享盘掉线", "active（running）· enabled", "green"),
    ("nfs", "NFS 共享", "core", "systemd", "nfs-server.service", "媒体库只读挂载", "", "inactive（dead）· disabled", "gray"),
    ("smartd", "磁盘健康监测", "app", "systemd", "smartd.service", "S.M.A.R.T. 告警", "", "active（running）· enabled", "green"),
    ("snapraid", "SnapRAID 校验", "app", "systemd", "snapraid-sync.timer", "每日校验同步", "", "active（waiting）· enabled", "green"),
    ("backup", "每日备份", "app", "systemd", "nas-backup.timer", "配置与照片增量备份", "", "active（waiting）· enabled", "green"),
    ("cloudflared", "Cloudflare 隧道", "net", "systemd", "cloudflared.service", "外网入口隧道", "", "active（running）· enabled", "green"),
    ("nginx", "反向代理", "net", "docker", "nas-proxy", "统一 80/443 入口", "", "running · healthy", "green"),
]

CONTAINERS = [
    ("jellyfin", "jellyfin/jellyfin:10.9.11", "running", "healthy", "Up 6 days", "媒体服务器", "green"),
    ("qbittorrent", "lscr.io/linuxserver/qbittorrent:latest", "running", "none", "Up 6 days", "下载器", "green"),
    ("nextcloud", "nextcloud:29-apache", "running", "healthy", "Up 3 days", "私有网盘", "green"),
    ("mariadb", "mariadb:11.4", "running", "healthy", "Up 6 days", "nextcloud 数据库", "green"),
    ("immich-server", "ghcr.io/immich-app/immich-server:v1.118", "running", "healthy", "Up 2 days", "照片备份", "green"),
    ("immich-ml", "ghcr.io/immich-app/immich-machine-learning:v1.118", "running", "none", "Up 2 days", "照片 AI 识别", "green"),
    ("photoprism", "photoprism/photoprism:240711", "exited", "none", "Exited (0) 12 days ago", "旧照片库（已停用）", "gray"),
    ("syncthing", "syncthing/syncthing:1.27", "running", "healthy", "Up 6 days", "多端同步", "green"),
    ("homeassistant", "ghcr.io/home-assistant/home-assistant:2024.11", "running", "none", "Up 9 days", "智能家居", "green"),
    ("portainer", "portainer/portainer-ce:2.20", "running", "none", "Up 6 days", "容器管理界面", "green"),
    ("redis", "redis:7-alpine", "running", "healthy", "Up 6 days", "缓存", "green"),
    ("nas-proxy", "nginx:1.27-alpine", "running", "healthy", "Up 6 days", "统一入口反代", "green"),
]

def svc(entry):
    sid, name, grp, kind, unit_or_name, note, warn, detail, status = entry
    d = dict(id=sid, name=name, group=grp, kind=kind, note=note, warn=warn, detail=detail, status=status)
    if kind == "systemd":
        d["unit"] = unit_or_name
        d["actions"] = ["stop", "restart"] if status != "gray" else ["start"]
    else:
        d["container"] = unit_or_name
        d["actions"] = ["restart"]
    return d

def ct(entry):
    name, image, state, health, uptime, note, status = entry
    return dict(name=name, image=image, state=state, health=health, uptime=uptime, ports="",
                note=note, warn="", detail=("已关闭" if state == "exited" else "running · manifest 正常"),
                autoremove=False, status=status,
                actions=["start"] if state == "exited" else ["stop", "restart"])

def series(base, jitter, n=48):
    v, out = base, []
    for _ in range(n):
        v = max(1.0, min(99.0, v + random.uniform(-jitter, jitter)))
        out.append(round(v, 1))
    return out

total = 8 * 1024 ** 3
used = int(total * 0.42)
state = {
    "ts": now,
    "host": {
        "hostname": "node-01",
        "kernel": "6.8.0-45-generic",
        "os": "Ubuntu 24.04 LTS",
        "load": [0.62, 0.55, 0.48],
        "cpu": {"cores": 4, "pct": 18.4},
        "uptime": "12天6小时",
        "mem": {"total": total, "used": used, "pct": 42.0},
        "swap": {"total": 2 * 1024 ** 3, "used": int(2 * 1024 ** 3 * 0.12), "pct": 12.0},
        "disk": {"total": 4 * 1024 ** 4, "used": int(4 * 1024 ** 4 * 0.63), "pct": 63.0},
    },
    "sys": {
        "kernel": "6.8.0-45-generic",
        "hostname": "node-01",
        "os": "Ubuntu 24.04 LTS",
        "last_update": datetime.datetime.now().timestamp() - 86400 * 5,
        "reboot_required": False,
        "updates": {"count": 6, "security": 2,
                    "packages": ["linux-image-6.8.0-46-generic", "libssl3t64", "openssh-server",
                                 "curl", "containerd.io", "docker-ce"],
                    "error": None, "checked": now},
        "pkg_total": 1187,
        "ifaces": [
            {"name": "eno1", "state": "up", "up": True, "carrier": True, "status": "ok",
             "speed": 1000, "speed_max": 2500, "mac": "aa:bb:cc:00:11:01", "mtu": 1500, "ipv4": "192.168.10.2"},
            {"name": "eno2", "state": "up", "up": True, "carrier": True, "status": "warn",
             "speed": 100, "speed_max": 2500, "mac": "aa:bb:cc:00:11:02", "mtu": 1500, "ipv4": "192.168.66.1"},
            {"name": "eno3", "state": "down", "up": False, "carrier": False, "status": "down",
             "speed": None, "speed_max": 2500, "mac": "aa:bb:cc:00:11:03", "mtu": 1500, "ipv4": ""},
            {"name": "eno4", "state": "down", "up": False, "carrier": False, "status": "down",
             "speed": None, "speed_max": 2500, "mac": "aa:bb:cc:00:11:04", "mtu": 1500, "ipv4": ""},
        ],
    },
    "network": {"status": "green", "items": [
        {"id": "route", "label": "默认路由", "status": "green", "detail": "→ 192.168.10.1 dev eno1"},
        {"id": "gw", "label": "光猫 192.168.10.1", "status": "green", "detail": "延迟 1ms"},
        {"id": "wan", "label": "外网 IPv4", "status": "green", "detail": "延迟 12ms"},
        {"id": "dns", "label": "DNS 解析", "status": "green", "detail": "example.com 正常"},
        {"id": "lan", "label": "内网网关 192.168.66.1", "status": "green", "detail": "延迟 0ms"},
        {"id": "tunnel", "label": "Cloudflare 隧道", "status": "green", "detail": "cloudflared ready"},
        {"id": "storage", "label": "存储池", "status": "green", "detail": "4 盘 · 无降级"},
    ]},
    "proxy": {"ok": False, "error": "演示环境未安装代理组件", "running": False, "nodes": [],
              "subscription": "", "mixed_port": "", "mode": ""},
    "services": [svc(x) for x in SERVICES],
    "containers": [ct(x) for x in CONTAINERS],
    "docker_error": "",
    "history": {"cpu": series(18, 6), "mem": series(42, 3), "swap": series(12, 1.5),
                "disk": series(63, 0.3), "net_rx": series(30, 20), "net_tx": series(12, 8),
                "ts": [now] * 48},
    "traffic": {"ts": now, "hours": 24, "rows": [], "total_req": 0, "total_bytes": 0,
                "total_err": 0, "warm": True, "live": {}, "live_ts": 0},
    "counts": {"services": len(SERVICES), "green": 5, "yellow": 0, "red": 0, "gray": 1,
               "containers": len(CONTAINERS)},
}

disk = {
    "ts": now, "scanning": False,
    "df": {"total": 931.5, "used": 586.7, "pct": 63.0},
    "docker": {"images": 21, "images_gb": 18.4, "volumes": 9, "volumes_gb": 4.1,
               "build_cache_gb": 2.6, "total_gb": 25.1},
    "dirs": [
        {"path": "/srv/media", "gb": 312.4, "pct": 33.5},
        {"path": "/srv/photos", "gb": 148.2, "pct": 15.9},
        {"path": "/srv/docker", "gb": 96.8, "pct": 10.4},
        {"path": "/srv/backup", "gb": 61.3, "pct": 6.6},
        {"path": "/var/log", "gb": 8.9, "pct": 1.0},
        {"path": "/opt", "gb": 5.4, "pct": 0.6},
    ],
}

clean = {"total": 0, "rows": []}

here = os.path.dirname(os.path.abspath(__file__))
for name, obj in (("state.json", state), ("disk.json", disk), ("cleanable.json", clean)):
    with open(os.path.join(here, "fixtures", name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
print("fixtures written")

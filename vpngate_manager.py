#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", str(12 * 60 * 60)))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "1260"))
TARGET_VALID_NODES = int(os.environ.get("TARGET_VALID_NODES", "5"))
AUTO_REFRESH_COOLDOWN_SECONDS = int(os.environ.get("AUTO_REFRESH_COOLDOWN_SECONDS", str(60 * 60)))
COLLECTOR_DECISION_INTERVAL_SECONDS = int(os.environ.get("COLLECTOR_DECISION_INTERVAL_SECONDS", "30"))
# 【优化】将默认单次从 API 扫描的最大节点数量从 300 提升到 2000
# 这样可以一次性把官方 API 接口返回的所有可用节点全部吃进内存
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "2000"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
# 将原本的 "127.0.0.1" 修改为 "0.0.0.0"，以允许公网的 hy2 节点连接本机的代理端口
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "0.0.0.0")
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = int(os.environ.get("UI_PORT", "8787"))
INVALID_BACKOFF_SECONDS = int(os.environ.get("INVALID_BACKOFF_SECONDS", str(30 * 60)))
MIRROR_SITES_URL = os.environ.get("MIRROR_SITES_URL", "https://www.vpngate.net/en/sites.aspx")
MIRROR_SITES_URLS = os.environ.get("MIRROR_SITES_URLS", "")
ENABLE_MIRROR_AGGREGATION = str(os.environ.get("ENABLE_MIRROR_AGGREGATION", "1")).strip().lower() not in ("0", "false", "no", "off")
MAX_MIRROR_SOURCES = int(os.environ.get("MAX_MIRROR_SOURCES", "4"))
MIRROR_LIST_CACHE_SECONDS = int(os.environ.get("MIRROR_LIST_CACHE_SECONDS", "1800"))
EXTRA_VPNGATE_API_URLS = os.environ.get("EXTRA_VPNGATE_API_URLS", "")
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "500"))
MAX_CONCURRENT_TEST_WORKERS = int(os.environ.get("MAX_CONCURRENT_TEST_WORKERS", "2"))
MAX_BATCH_TEST_REQUEST_SIZE = int(os.environ.get("MAX_BATCH_TEST_REQUEST_SIZE", "12"))
MAX_MAINTAIN_TEST_NODES = int(os.environ.get("MAX_MAINTAIN_TEST_NODES", "12"))
FOLLOWUP_TEST_BATCH_SIZE = int(os.environ.get("FOLLOWUP_TEST_BATCH_SIZE", "5"))
SOURCE_SCAN_CANDIDATE_LIMIT = int(os.environ.get("SOURCE_SCAN_CANDIDATE_LIMIT", "10"))
FETCH_SOURCE_LIMIT = int(os.environ.get("FETCH_SOURCE_LIMIT", "5"))
SOURCE_DELETE_FAILURE_THRESHOLD = int(os.environ.get("SOURCE_DELETE_FAILURE_THRESHOLD", "3"))
MANUAL_TEST_TIMEOUT_SECONDS = int(os.environ.get("MANUAL_TEST_TIMEOUT_SECONDS", "8"))
KEEP_OLD_NODE_LATENCY_MS = int(os.environ.get("KEEP_OLD_NODE_LATENCY_MS", "50"))
MAX_CACHED_NODES = int(os.environ.get("MAX_CACHED_NODES", "1200"))

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
SOURCES_FILE = DATA_DIR / "api_sources.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"

lock = threading.RLock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
proxy_health_failures = 0
last_active_ping_time = 0.0
last_active_latency = 0
PROXY_HEALTH_FAILURE_THRESHOLD = 3

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()
mirror_api_urls_cache: list[str] = []
mirror_api_urls_cache_expires_at = 0.0
maintain_job_lock = threading.Lock()
followup_test_lock = threading.Lock()
source_scan_lock = threading.Lock()
heavy_task_lock = threading.RLock()

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass
    if not SOURCES_FILE.exists():
        write_json(
            SOURCES_FILE,
            {
                "use_selected_only": False,
                "last_scan_at": 0.0,
                "last_scan_date": "",
                "last_scan_message": "",
                "sources": [
                    {
                        "url": API_URL,
                        "type": "system",
                        "enabled": True,
                        "selected": True,
                        "healthy": False,
                        "status": "待扫描",
                        "consecutive_failures": 0,
                        "success_count": 0,
                        "failure_count": 0,
                        "last_error": "",
                        "last_http_code": 0,
                        "last_checked_at": 0.0,
                        "last_success_at": 0.0,
                    }
                ],
            },
        )

def save_node_config(config_path: Path, config_text: str) -> None:
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    config_path.parent.mkdir(exist_ok=True, parents=True)
    if config_path.exists():
        try:
            if config_path.read_text(encoding="utf-8") == config_text:
                return
        except Exception:
            pass
    config_path.write_text(config_text, encoding="utf-8")

def write_json(path: Path, data: Any) -> None:
    if path == NODES_FILE and isinstance(data, list):
        stripped_nodes = []
        for item in data:
            if not isinstance(item, dict):
                stripped_nodes.append(item)
                continue
            node = dict(item)
            config_text = str(node.pop("config_text", "") or "")
            config_file = str(node.get("config_file") or "").strip()
            if config_text and config_file:
                try:
                    save_node_config(Path(config_file), config_text)
                except Exception:
                    pass
            stripped_nodes.append(node)
        data = stripped_nodes
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": "::",
            "port": 8787,
            "proxy_port": 7928,
            "proxy_user": "",
            "proxy_pass": "",
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "routing_protocol": ["udp"],
            "connection_enabled": True,
            "fixed_node_id": ""
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["proxy_port", "proxy_user", "proxy_pass", "routing_mode", "force_country", "routing_ip_type", "routing_protocol", "connection_enabled", "fixed_node_id"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config

def get_proxy_listen_url() -> str:
    proxy_host = LOCAL_PROXY_HOST
    if ":" in proxy_host:
        proxy_host = f"[{proxy_host}]"
    return f"http://{proxy_host}:{LOCAL_PROXY_PORT}"

def get_proxy_display_url() -> str:
    proxy_host = LOCAL_PROXY_HOST
    if proxy_host in ("0.0.0.0", "", "::"):
        try:
            public_ip = (DATA_DIR / "public_ip.txt").read_text(encoding="utf-8").strip()
            if public_ip:
                proxy_host = public_ip
        except Exception:
            pass
    if ":" in proxy_host:
        proxy_host = f"[{proxy_host}]"
    return f"http://{proxy_host}:{LOCAL_PROXY_PORT}"

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = int(_init_cfg["proxy_port"])
    if "port" in _init_cfg:
        UI_PORT = int(_init_cfg["port"])
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)



def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_fetch_message", "")
    state.setdefault("last_check_message", "")
    state.setdefault("valid_nodes", 0)
    state.setdefault("routed_valid_nodes", 0)
    state.setdefault("blacklisted_nodes", 0)
    state.setdefault("auto_refresh_completed_at", 0.0)
    state.setdefault("auto_refresh_cooldown_until", 0.0)
    state.setdefault("last_auto_refresh_reason", "")
    state["local_proxy"] = get_proxy_listen_url()
    state["proxy_entry"] = get_proxy_display_url()

    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["proxy_user"] = ui_cfg.get("proxy_user", "")
    state["proxy_pass"] = ui_cfg.get("proxy_pass", "")
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["routing_protocol"] = normalize_routing_protocols(ui_cfg.get("routing_protocol", ["udp"]))
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    source_pool = load_source_pool()
    state["source_use_selected_only"] = source_pool.get("use_selected_only", False)
    state["source_last_scan_at"] = float(source_pool.get("last_scan_at", 0) or 0)
    state["source_last_scan_message"] = str(source_pool.get("last_scan_message", "") or "")
    state["source_total_count"] = len(source_pool.get("sources", []))
    state["healthy_source_count"] = len([item for item in source_pool.get("sources", []) if item.get("healthy")])
    return state

def normalize_source_url(url: Any) -> str:
    text = str(url or "").strip()
    if not text or not re.match(r"^https?://", text, re.IGNORECASE):
        return ""
    text = text.rstrip("/")
    lowered = text.lower()
    if lowered.endswith("/api/iphone"):
        return text + "/"
    if "/api/iphone/" in lowered:
        idx = lowered.find("/api/iphone/")
        return text[:idx] + "/api/iphone/"
    return text + "/api/iphone/"

def default_source_entry(url: str, source_type: str = "mirror") -> dict[str, Any]:
    return {
        "url": url,
        "type": source_type,
        "enabled": True,
        "selected": source_type in ("system", "manual"),
        "healthy": False,
        "status": "待扫描",
        "consecutive_failures": 0,
        "success_count": 0,
        "failure_count": 0,
        "last_error": "",
        "last_http_code": 0,
        "last_checked_at": 0.0,
        "last_success_at": 0.0,
    }

def source_type_order(source_type: Any) -> int:
    if source_type == "system":
        return 0
    if source_type == "manual":
        return 1
    return 2

def sort_source_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        entries,
        key=lambda item: (
            0 if item.get("healthy") else 1,
            source_type_order(item.get("type")),
            0 if item.get("enabled") else 1,
            -float(item.get("last_success_at", 0) or 0),
            str(item.get("url") or ""),
        ),
    )

def normalize_deleted_source_urls(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    urls: list[str] = []
    for item in values:
        url = normalize_source_url(item)
        if url and url not in urls:
            urls.append(url)
    return urls

def load_source_pool() -> dict[str, Any]:
    try:
        raw = read_json(SOURCES_FILE, {})
    except Exception:
        raw = {}

    deleted_urls = normalize_deleted_source_urls(raw.get("deleted_urls", []))
    deleted_url_set = set(deleted_urls)
    entries_by_url: dict[str, dict[str, Any]] = {}
    raw_sources = raw.get("sources", [])
    if not isinstance(raw_sources, list):
        raw_sources = []

    for item in raw_sources:
        if not isinstance(item, dict):
            continue
        url = normalize_source_url(item.get("url"))
        if not url:
            continue
        if url in deleted_url_set:
            continue
        source_type = str(item.get("type") or "mirror").strip().lower()
        if source_type not in ("system", "manual", "mirror"):
            source_type = "mirror"
        entry = default_source_entry(url, source_type)
        entry["enabled"] = bool(item.get("enabled", True))
        entry["selected"] = entry["enabled"]
        entry["healthy"] = bool(item.get("healthy", False))
        entry["status"] = str(item.get("status") or "待扫描")
        entry["consecutive_failures"] = max(0, parse_int(item.get("consecutive_failures")))
        entry["success_count"] = max(0, parse_int(item.get("success_count")))
        entry["failure_count"] = max(0, parse_int(item.get("failure_count")))
        entry["last_error"] = str(item.get("last_error") or "")
        entry["last_http_code"] = max(0, parse_int(item.get("last_http_code")))
        entry["last_checked_at"] = float(item.get("last_checked_at", 0) or 0)
        entry["last_success_at"] = float(item.get("last_success_at", 0) or 0)
        entries_by_url[url] = entry

    system_url = normalize_source_url(API_URL)
    if system_url and system_url not in entries_by_url and system_url not in deleted_url_set:
        entries_by_url[system_url] = default_source_entry(system_url, "system")

    return {
        "use_selected_only": bool(raw.get("use_selected_only", False)),
        "deleted_urls": deleted_urls,
        "last_scan_at": float(raw.get("last_scan_at", 0) or 0),
        "last_scan_date": str(raw.get("last_scan_date") or ""),
        "last_scan_message": str(raw.get("last_scan_message") or ""),
        "sources": sort_source_entries(list(entries_by_url.values())),
    }

def save_source_pool(pool: dict[str, Any]) -> dict[str, Any]:
    deleted_urls = normalize_deleted_source_urls(pool.get("deleted_urls", []))
    deleted_url_set = set(deleted_urls)
    normalized = {
        "use_selected_only": bool(pool.get("use_selected_only", False)),
        "deleted_urls": deleted_urls,
        "last_scan_at": float(pool.get("last_scan_at", 0) or 0),
        "last_scan_date": str(pool.get("last_scan_date") or ""),
        "last_scan_message": str(pool.get("last_scan_message") or ""),
        "sources": sort_source_entries([
            item
            for item in list(pool.get("sources", []))
            if normalize_source_url(item.get("url")) not in deleted_url_set
        ]),
    }
    write_json(SOURCES_FILE, normalized)
    return normalized

def looks_like_vpngate_csv(text: str) -> bool:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("*"):
            continue
        if line.startswith("#"):
            line = line[1:]
        return all(key in line for key in ("HostName", "IP", "Score", "OpenVPN_ConfigData_Base64"))
    return False

def parse_http_code_from_error(exc: Exception) -> int:
    text = str(exc)
    match = re.search(r"(?:HTTP Error|status)\s+(\d{3})", text, re.IGNORECASE)
    return int(match.group(1)) if match else 0

def probe_api_source(source_url: str) -> dict[str, Any]:
    started_at = time.time()
    try:
        text = fetch_api_text(source_url, use_ssl_verify=source_url.startswith("https://"))
        if not looks_like_vpngate_csv(text):
            raise RuntimeError("返回内容不是 api/iphone CSV")
        return {
            "ok": True,
            "http_code": 200,
            "error": "",
            "checked_at": started_at,
        }
    except Exception as exc:
        return {
            "ok": False,
            "http_code": parse_http_code_from_error(exc),
            "error": str(exc),
            "checked_at": started_at,
        }

def source_page_urls() -> list[str]:
    raw_urls = [MIRROR_SITES_URL]
    if MIRROR_SITES_URLS:
        raw_urls.extend(re.split(r"[\s,]+", MIRROR_SITES_URLS.strip()))
    seen: set[str] = set()
    urls: list[str] = []
    for item in raw_urls:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        urls.append(text)
    return urls

def load_mirror_site_urls() -> list[str]:
    if not ENABLE_MIRROR_AGGREGATION:
        return []

    cache_file = DATA_DIR / "mirror_sites_cache.json"
    now = time.time()
    try:
        cache = read_json(cache_file, {})
        cached_at = float(cache.get("cached_at", 0) or 0)
        cached_urls = cache.get("urls", [])
        if now - cached_at <= MIRROR_LIST_CACHE_SECONDS and isinstance(cached_urls, list):
            return [normalize_source_url(item) for item in cached_urls if normalize_source_url(item)]
    except Exception:
        pass

    urls: list[str] = []
    for page_url in source_page_urls():
        try:
            text = fetch_api_text(page_url)
        except Exception as exc:
            print(f"[源扫描] 获取官方镜像页失败: {page_url} -> {exc}", flush=True)
            log_to_json("WARNING", "Main", f"官方镜像页获取失败: {page_url} -> {exc}")
            continue
        for match in re.findall(r"https?://[A-Za-z0-9._:/?=&%-]+", text):
            candidate = normalize_source_url(match)
            if candidate and candidate not in urls:
                urls.append(candidate)
        if len(urls) >= SOURCE_SCAN_CANDIDATE_LIMIT:
            break

    urls = urls[:SOURCE_SCAN_CANDIDATE_LIMIT]
    try:
        write_json(cache_file, {"cached_at": now, "urls": urls})
    except Exception:
        pass
    return urls

def collect_source_scan_candidates(pool: dict[str, Any]) -> list[str]:
    deleted_url_set = set(normalize_deleted_source_urls(pool.get("deleted_urls", [])))
    urls: list[str] = []
    for item in sort_source_entries(list(pool.get("sources", []))):
        if item.get("type") not in ("system", "manual"):
            continue
        url = normalize_source_url(item.get("url"))
        if url and url not in deleted_url_set and url not in urls:
            urls.append(url)
    for item in load_mirror_site_urls():
        url = normalize_source_url(item)
        if url and url not in deleted_url_set and url not in urls:
            urls.append(url)
    return urls[:SOURCE_SCAN_CANDIDATE_LIMIT]

def update_source_entry_with_probe(entry: dict[str, Any], result: dict[str, Any]) -> None:
    checked_at = float(result.get("checked_at", time.time()) or time.time())
    entry["last_checked_at"] = checked_at
    entry["last_http_code"] = max(0, parse_int(result.get("http_code")))
    if result.get("ok"):
        entry["healthy"] = True
        entry["status"] = "可用"
        entry["last_error"] = ""
        entry["consecutive_failures"] = 0
        entry["success_count"] = max(0, parse_int(entry.get("success_count"))) + 1
        entry["last_success_at"] = checked_at
    else:
        entry["healthy"] = False
        entry["status"] = "不可用"
        entry["last_error"] = str(result.get("error") or "连接失败")
        entry["failure_count"] = max(0, parse_int(entry.get("failure_count"))) + 1
        entry["consecutive_failures"] = max(0, parse_int(entry.get("consecutive_failures"))) + 1

def run_source_scan(force: bool = False) -> dict[str, Any]:
    if not source_scan_lock.acquire(blocking=False):
        return {"ok": False, "message": "源扫描正在进行中"}
    try:
        heavy_task_lock.acquire()
        pool = load_source_pool()
        now = time.time()
        date_str = time.strftime("%Y-%m-%d", time.localtime(now))
        if not force and pool.get("last_scan_date") == date_str:
            return {"ok": False, "message": "今天的源扫描已经执行过"}

        entries_by_url = {
            normalize_source_url(item.get("url")): dict(item)
            for item in pool.get("sources", [])
            if normalize_source_url(item.get("url"))
        }
        deleted_url_set = set(normalize_deleted_source_urls(pool.get("deleted_urls", [])))
        candidates = collect_source_scan_candidates(pool)
        scanned = 0
        healthy = 0
        removed = 0
        added = 0

        for source_url in candidates:
            if source_url in deleted_url_set:
                continue
            if source_url not in entries_by_url:
                entries_by_url[source_url] = default_source_entry(source_url, "mirror")
                added += 1
            entry = entries_by_url[source_url]
            result = probe_api_source(source_url)
            update_source_entry_with_probe(entry, result)
            scanned += 1
            if result.get("ok"):
                healthy += 1

        kept_sources: list[dict[str, Any]] = []
        for item in entries_by_url.values():
            if item.get("type") != "system" and parse_int(item.get("consecutive_failures")) >= SOURCE_DELETE_FAILURE_THRESHOLD:
                removed += 1
                continue
            kept_sources.append(item)

        message = f"源扫描完成：检测 {scanned} 个，健康 {healthy} 个，新增 {added} 个，删除 {removed} 个"
        pool["last_scan_at"] = now
        pool["last_scan_date"] = date_str
        pool["last_scan_message"] = message
        pool["sources"] = sort_source_entries(kept_sources)
        saved_pool = save_source_pool(pool)
        set_state(
            source_last_scan_at=now,
            source_last_scan_message=message,
            source_total_count=len(saved_pool.get("sources", [])),
            healthy_source_count=len([item for item in saved_pool.get("sources", []) if item.get("healthy")]),
        )
        log_to_json("INFO", "Main", message)
        return {"ok": True, "message": message, "pool": saved_pool}
    finally:
        heavy_task_lock.release()
        source_scan_lock.release()

def schedule_source_scan(force: bool = False) -> bool:
    if source_scan_lock.locked():
        return False

    def worker() -> None:
        try:
            run_source_scan(force=force)
        except Exception as exc:
            print(f"[源扫描] 执行失败: {exc}", flush=True)
            log_to_json("WARNING", "Main", f"源扫描失败: {exc}")

    threading.Thread(target=worker, daemon=True).start()
    return True

def should_run_daily_source_scan(now: float) -> bool:
    pool = load_source_pool()
    date_str = time.strftime("%Y-%m-%d", time.localtime(now))
    local_time = time.localtime(now)
    return local_time.tm_hour == 0 and pool.get("last_scan_date") != date_str

def update_source_runtime_result(source_url: str, ok: bool, error: str = "", http_code: int = 0) -> None:
    normalized_url = normalize_source_url(source_url)
    if not normalized_url:
        return
    pool = load_source_pool()
    entries = {item.get("url"): dict(item) for item in pool.get("sources", []) if item.get("url")}
    if normalized_url not in entries:
        return
    result = {
        "ok": ok,
        "error": error,
        "http_code": http_code,
        "checked_at": time.time(),
    }
    update_source_entry_with_probe(entries[normalized_url], result)
    pool["sources"] = [
        item
        for item in sort_source_entries(list(entries.values()))
        if item.get("type") == "system" or parse_int(item.get("consecutive_failures")) < SOURCE_DELETE_FAILURE_THRESHOLD
    ]
    save_source_pool(pool)

def get_active_fetch_source_urls() -> list[str]:
    pool = load_source_pool()
    deleted_url_set = set(normalize_deleted_source_urls(pool.get("deleted_urls", [])))

    def pick_urls() -> list[str]:
        entries = [item for item in pool.get("sources", []) if item.get("enabled")]
        entries = [item for item in entries if item.get("healthy")]
        return [str(item.get("url") or "") for item in sort_source_entries(entries)[:FETCH_SOURCE_LIMIT] if str(item.get("url") or "")]

    urls = pick_urls()
    if urls:
        return urls

    scan_result = run_source_scan(force=True)
    if scan_result.get("ok"):
        pool = scan_result.get("pool", pool)
        urls = pick_urls()
        if urls:
            return urls

    fallback = normalize_source_url(API_URL)
    if fallback in deleted_url_set:
        return []
    return [fallback] if fallback else []

def source_pool_public_data() -> dict[str, Any]:
    pool = load_source_pool()
    return {
        "use_selected_only": bool(pool.get("use_selected_only", False)),
        "last_scan_at": float(pool.get("last_scan_at", 0) or 0),
        "last_scan_message": str(pool.get("last_scan_message", "") or ""),
        "scan_running": source_scan_lock.locked(),
        "sources": sort_source_entries(list(pool.get("sources", []))),
    }

def probe_single_source(url: str) -> dict[str, Any]:
    normalized_url = normalize_source_url(url)
    if not normalized_url:
        raise ValueError("源地址不能为空")
    if not source_scan_lock.acquire(blocking=False):
        raise RuntimeError("源扫描正在进行中，请稍后再试")
    try:
        pool = load_source_pool()
        sources = [dict(item) for item in pool.get("sources", [])]
        target_entry: dict[str, Any] | None = None
        for item in sources:
            if normalize_source_url(item.get("url")) == normalized_url:
                target_entry = item
                break
        if target_entry is None:
            raise ValueError("未找到对应的源")

        result = probe_api_source(normalized_url)
        update_source_entry_with_probe(target_entry, result)
        pool["sources"] = sort_source_entries(sources)
        saved_pool = save_source_pool(pool)
        saved_entry = next(
            (dict(item) for item in saved_pool.get("sources", []) if normalize_source_url(item.get("url")) == normalized_url),
            dict(target_entry),
        )
        return {"pool": saved_pool, "entry": saved_entry, "result": result}
    finally:
        source_scan_lock.release()

def add_manual_source(url: str) -> dict[str, Any]:
    normalized_url = normalize_source_url(url)
    if not normalized_url:
        raise ValueError("源地址格式不正确，必须是 http/https")
    pool = load_source_pool()
    deleted_urls = [item for item in normalize_deleted_source_urls(pool.get("deleted_urls", [])) if item != normalized_url]
    pool["deleted_urls"] = deleted_urls
    sources = [dict(item) for item in pool.get("sources", [])]
    for item in sources:
        if normalize_source_url(item.get("url")) == normalized_url:
            item["type"] = "manual"
            item["enabled"] = True
            item["selected"] = True
            pool["sources"] = sources
            return save_source_pool(pool)
    sources.append(default_source_entry(normalized_url, "manual"))
    pool["sources"] = sources
    return save_source_pool(pool)

def delete_source(url: str) -> dict[str, Any]:
    normalized_url = normalize_source_url(url)
    if not normalized_url:
        raise ValueError("源地址不能为空")
    pool = load_source_pool()
    kept: list[dict[str, Any]] = []
    removed = False
    for item in pool.get("sources", []):
        if normalize_source_url(item.get("url")) == normalized_url:
            removed = True
            continue
        kept.append(dict(item))
    if not removed:
        raise ValueError("未找到对应的源")
    pool["sources"] = kept
    deleted_urls = normalize_deleted_source_urls(pool.get("deleted_urls", []))
    if normalized_url not in deleted_urls:
        deleted_urls.append(normalized_url)
    pool["deleted_urls"] = deleted_urls
    return save_source_pool(pool)

def update_source_flags(url: str, *, enabled: bool | None = None, selected: bool | None = None) -> dict[str, Any]:
    normalized_url = normalize_source_url(url)
    if not normalized_url:
        raise ValueError("源地址不能为空")
    pool = load_source_pool()
    changed = False
    updated_sources: list[dict[str, Any]] = []
    for item in pool.get("sources", []):
        current = dict(item)
        if normalize_source_url(current.get("url")) == normalized_url:
            next_enabled = enabled
            if next_enabled is None and selected is not None:
                next_enabled = bool(selected)
            if next_enabled is not None:
                current["enabled"] = bool(next_enabled)
                current["selected"] = bool(next_enabled)
            changed = True
        updated_sources.append(current)
    if not changed:
        raise ValueError("未找到对应的源")
    pool["sources"] = updated_sources
    return save_source_pool(pool)

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def normalize_protocol_name(value: Any) -> str:
    proto = str(value or "").strip().lower()
    if proto.startswith("tcp"):
        return "tcp"
    if proto == "udp":
        return "udp"
    return ""

def normalize_routing_protocols(value: Any) -> list[str]:
    if isinstance(value, str):
        preset = {
            "all": ["tcp", "udp"],
            "tcp_only": ["tcp"],
            "udp_only": ["udp"],
        }
        values = preset.get(value.strip().lower(), [value])
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = []

    protocols: list[str] = []
    for item in values:
        proto = normalize_protocol_name(item)
        if proto and proto not in protocols:
            protocols.append(proto)
    return protocols or ["udp"]

def node_protocol(node: dict[str, Any]) -> str:
    return normalize_protocol_name(node.get("proto"))

def apply_protocol_filter(nodes: list[dict[str, Any]], routing_protocols: Any) -> list[dict[str, Any]]:
    allowed = set(normalize_routing_protocols(routing_protocols))
    return [node for node in nodes if node_protocol(node) in allowed]

def node_endpoint_key(node: dict[str, Any]) -> tuple[str, int, str]:
    host = str(node.get("ip") or node.get("remote_host") or "").strip().lower()
    port = parse_int(node.get("remote_port"))
    proto = node_protocol(node)
    return host, port, proto

def merge_node_runtime_fields(base_node: dict[str, Any], old_node: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base_node)
    for key in [
        "latency_ms",
        "probe_status",
        "probe_message",
        "probed_at",
        "owner",
        "asn",
        "as_name",
        "location",
        "ip_type",
        "quality",
        "active",
        "fetched_at",
        "is_testing",
    ]:
        if key in old_node:
            merged[key] = old_node.get(key)
    return merged

def legacy_fetch_text_from_many(urls: list[str]) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for url in urls:
        try:
            text = fetch_api_text(url, use_ssl_verify=url.startswith("https://"))
            if text.strip():
                results.append((url, text))
        except Exception as exc:
            print(f"[抓取节点] 来源失败: {url} -> {exc}", flush=True)
            log_to_json("WARNING", "Main", f"节点来源失败: {url} -> {exc}")
    return results

def legacy_load_mirror_site_urls() -> list[str]:
    if not ENABLE_MIRROR_AGGREGATION:
        return []

    cache_file = DATA_DIR / "mirror_sites_cache.json"
    now = time.time()
    try:
        cache = read_json(cache_file, {})
        cached_at = float(cache.get("cached_at", 0))
        cached_urls = cache.get("urls", [])
        if now - cached_at <= MIRROR_LIST_CACHE_SECONDS and isinstance(cached_urls, list):
            return [str(item) for item in cached_urls if str(item).strip()]
    except Exception:
        pass

    urls: list[str] = []
    for source_url in MIRROR_SITES_URLS:
        try:
            text = fetch_api_text(source_url)
        except Exception as exc:
            print(f"[镜像列表] 获取失败: {source_url} -> {exc}", flush=True)
            continue
        for match in re.findall(r"https?://[A-Za-z0-9._:/?=&%-]+", text):
            clean = match.rstrip("/ \t\r\n")
            if clean not in urls:
                urls.append(clean)

    urls = urls[:MAX_MIRROR_SOURCES]
    try:
        write_json(cache_file, {"cached_at": now, "urls": urls})
    except Exception:
        pass
    return urls

def legacy_collect_candidate_source_urls() -> list[str]:
    urls: list[str] = []
    for item in [API_URL, *EXTRA_VPNGATE_API_URLS]:
        if item and item not in urls:
            urls.append(item)

    for mirror_url in load_mirror_site_urls():
        api_url = mirror_url.rstrip("/") + "/api/iphone/"
        if api_url not in urls:
            urls.append(api_url)
    return urls

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        if ptype == "socks":
            # SOCKS5 Handshake
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            # SOCKS5 Connect
            domain_bytes = domain.encode('ascii')
            req = b"\x05\x01\x00\x03" + bytes([len(domain_bytes)]) + domain_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            resp = s.recv(10)
            if len(resp) < 4 or resp[1] != 0:
                raise RuntimeError("SOCKS5 connection request rejected")
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                req_str = f"CONNECT {domain}:{port} HTTP/1.1\r\nHost: {domain}:{port}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\nProxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = s.recv(4096)
                if not (b"200" in resp or b"established" in resp.lower() or b"ok" in resp.lower()):
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {resp.decode('utf-8', errors='replace')}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path
            
        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024: # max 10MB safety guard
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")


def ensure_node_config_path(node: dict[str, Any]) -> Path:
    config_file = str(node.get("config_file") or "").strip()
    if not config_file:
        raise RuntimeError("节点缺少配置文件路径")
    config_path = Path(config_file)
    if config_path.exists():
        return config_path
    config_text = str(node.get("config_text") or "")
    if not config_text:
        raise RuntimeError(f"节点配置文件不存在: {config_path}")
    save_node_config(config_path, config_text)
    return config_path

def load_blacklist() -> dict[str, dict[str, Any]]:
    return {}

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    pass

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(
        country_long,
        vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long),
    )
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "missing_from_latest_fetch": False,
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
        "active": False,
    }

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_endpoints: set[tuple[str, int, str]] = set()
    source_summaries: list[str] = []
    has_cache = len(cached_nodes()) > 0
    source_urls = get_active_fetch_source_urls()
    if not source_urls:
        source_urls = [API_URL]

    def fetch_rows_from_source(source_url: str, max_attempts: int) -> tuple[list[dict[str, str]], str]:
        attempts: list[tuple[str, bool]] = [(source_url, True)]
        if source_url.startswith("https://"):
            attempts.append((source_url, False))
            attempts.append((source_url.replace("https://", "http://", 1), True))

        last_error: Exception | None = None
        for url, verify_ssl in attempts:
            for attempt in range(max_attempts):
                if attempt > 0:
                    time.sleep(1.5)
                try:
                    api_text = fetch_api_text(url, verify_ssl)
                    rows = parse_vpngate_rows(api_text)
                    if rows:
                        return rows, url
                except Exception as exc:
                    last_error = exc
                    print(f"[抓取节点] 来源失败: {url} -> {exc}", flush=True)
                    log_to_json("WARNING", "Main", f"节点来源失败: {url} -> {exc}")
        if last_error is not None:
            raise last_error
        raise RuntimeError("未获取到任何节点数据")

    log_to_json("INFO", "Main", f"开始抓取节点，共 {len(source_urls)} 个来源")
    for index, source_url in enumerate(source_urls, start=1):
        try:
            rows, actual_url = fetch_rows_from_source(source_url, 1 if has_cache or index > 1 else 2)
            update_source_runtime_result(actual_url, True, "", 200)
        except Exception as exc:
            update_source_runtime_result(source_url, False, str(exc), parse_http_code_from_error(exc))
            source_summaries.append(f"来源{index}失败")
            continue

        added = 0
        for row in rows[:MAX_SCAN_ROWS]:
            encoded = row.get("OpenVPN_ConfigData_Base64", "")
            if not encoded:
                continue
            try:
                config_text = decode_config(encoded)
                node = row_to_node(row, config_text)
            except Exception:
                continue
            endpoint_key = node_endpoint_key(node)
            if endpoint_key in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_key)
            candidates.append(node)
            added += 1
        source_summaries.append(f"来源{index}+{added}")

    if not candidates:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        set_state(
            last_fetch_at=time.time(),
            last_fetch_status="error",
            last_fetch_error_code=err_code,
            last_fetch_message=diag_msg,
            blacklisted_nodes=len(blacklist),
        )
        raise RuntimeError(diag_msg)

    candidates = candidates[:MAX_CACHED_NODES]
    message = f"抓取到 {len(candidates)} 个候选节点，{' / '.join(source_summaries)}"
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=message,
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", message)
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_json(NODES_FILE, [])

_openvpn_version = None

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
        res = subprocess.run([cmd[0], "--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        # Terminate existing openvpn processes managing tun0 or using our vpngate configuration
        subprocess.run(["pkill", "-f", "openvpn.*tun0"], capture_output=True, timeout=2)
        subprocess.run(["pkill", "-f", "openvpn.*vpngate_data"], capture_output=True, timeout=2)
        print("[Cleanup] Terminated existing AimiliVPN OpenVPN processes.", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            if not startup_done[0]:
                lines.put(line.rstrip())
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line.rstrip()}", flush=True)
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-8:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    if not ok:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由")

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None


def filter_nodes_for_routing(nodes: list[dict[str, Any]], ui_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    filtered = list(nodes)
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = str(ui_cfg.get("force_country") or "").strip()
    if routing_mode == "fixed_region" and target_country:
        filtered = [node for node in filtered if node.get("country") == target_country]

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    if routing_ip_type == "residential":
        filtered = [node for node in filtered if node.get("ip_type") in ("residential", "mobile")]
    elif routing_ip_type == "hosting":
        filtered = [node for node in filtered if node.get("ip_type") == "hosting"]

    return apply_protocol_filter(filtered, ui_cfg.get("routing_protocol", ["udp"]))

def count_available_nodes_for_routing(nodes: list[dict[str, Any]], ui_cfg: dict[str, Any]) -> int:
    routed_nodes = filter_nodes_for_routing(nodes, ui_cfg)
    return len([node for node in routed_nodes if node.get("probe_status") == "available"])

def should_trigger_auto_refresh(state: dict[str, Any], available_count: int, now: float) -> tuple[bool, str]:
    cooldown_until = float(state.get("auto_refresh_cooldown_until", 0) or 0)
    last_refresh_at = float(state.get("auto_refresh_completed_at", 0) or 0)
    if cooldown_until > now:
        return False, "cooldown"
    if available_count < TARGET_VALID_NODES:
        return True, "low_stock"
    if now - last_refresh_at >= FETCH_INTERVAL_SECONDS:
        return True, "interval"
    return False, "wait"

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    active_nodes = [node for node in nodes if node.get("active")]
    available_nodes = sorted(
        [node for node in nodes if node.get("probe_status") == "available" and not node.get("active")],
        key=lambda node: (
            0 if node_protocol(node) == "udp" else 1,
            0 if node.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(node.get("latency_ms")) or 999999,
            -parse_int(node.get("score")),
        ),
    )
    unchecked_nodes = sorted(
        [node for node in nodes if node.get("probe_status") == "not_checked" and not node.get("active")],
        key=lambda node: (-parse_int(node.get("score")), parse_int(node.get("ping")) or 999999),
    )
    unavailable_nodes = sorted(
        [node for node in nodes if node.get("probe_status") == "unavailable" and not node.get("active")],
        key=lambda node: (-float(node.get("probed_at", 0)), -parse_int(node.get("score"))),
    )
    return active_nodes + available_nodes + unchecked_nodes + unavailable_nodes

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        return 99

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def set_node_testing_state(node_ids: list[str], is_testing: bool) -> None:
    normalized_ids = {str(node_id or "") for node_id in node_ids if str(node_id or "")}
    if not normalized_ids:
        return
    with lock:
        nodes = read_json(NODES_FILE, [])
        changed = False
        for item in nodes:
            node_id = str(item.get("id") or "")
            if node_id not in normalized_ids:
                continue
            if bool(item.get("is_testing")) == is_testing:
                continue
            item["is_testing"] = is_testing
            changed = True
        if changed:
            write_json(NODES_FILE, nodes)

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
    if not node:
        raise ValueError(f"未找到节点: {node_id}")

    config_path = ensure_node_config_path(node)
    remote_host = str(node.get("remote_host") or node.get("ip") or "")
    remote_port = parse_int(node.get("remote_port"))
    fallback_ping = parse_int(node.get("ping"))
    latency = vpn_utils.ping_latency_ms(remote_host, remote_port, fallback_ping)

    tun_idx = get_free_test_index()
    try:
        ok, message, _ = run_openvpn_until_ready(
            str(config_path),
            keep_alive=False,
            route_nopull=True,
            timeout=MANUAL_TEST_TIMEOUT_SECONDS,
            dev=f"tun{tun_idx}",
        )
    finally:
        release_test_index(tun_idx)

    result = {
        "id": node_id,
        "latency_ms": latency,
        "probe_status": "available" if ok else "unavailable",
        "probe_message": message,
        "probed_at": time.time(),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        enriched = [{
            "id": node_id,
            "ip": node.get("ip") or remote_host,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }]
        try:
            vpn_utils.enrich_ip_info(enriched)
            result.update({
                "owner": enriched[0].get("owner", ""),
                "asn": enriched[0].get("asn", ""),
                "as_name": enriched[0].get("as_name", ""),
                "location": enriched[0].get("location", ""),
                "ip_type": enriched[0].get("ip_type", ""),
                "quality": enriched[0].get("quality", ""),
            })
        except Exception:
            pass

    with lock:
        nodes = read_json(NODES_FILE, [])
        for item in nodes:
            if item.get("id") == node_id:
                item.update(result)
        sorted_nodes = sort_all_nodes(nodes)
        write_json(NODES_FILE, sorted_nodes)
        return next((item for item in sorted_nodes if item.get("id") == node_id), result)

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        to_test = [node for node in nodes if node.get("id") in node_ids]
    if not to_test:
        return []

    def worker(node: dict[str, Any]) -> dict[str, Any]:
        node_id = str(node.get("id") or "")
        try:
            config_path = ensure_node_config_path(node)
        except Exception as exc:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"读取配置失败: {exc}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }

        remote_host = str(node.get("remote_host") or node.get("ip") or "")
        remote_port = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))
        latency = vpn_utils.ping_latency_ms(remote_host, remote_port, fallback_ping)

        tun_idx = get_free_test_index()
        try:
            ok, message, _ = run_openvpn_until_ready(
                str(config_path),
                keep_alive=False,
                route_nopull=True,
                timeout=MANUAL_TEST_TIMEOUT_SECONDS,
                dev=f"tun{tun_idx}",
            )
        finally:
            release_test_index(tun_idx)

        return {
            "id": node_id,
            "ip": node.get("ip") or remote_host,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }

    results_map: dict[str, dict[str, Any]] = {}
    max_workers = min(MAX_CONCURRENT_TEST_WORKERS, max(1, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(worker, node): str(node.get("id") or "") for node in to_test}
        for future in concurrent.futures.as_completed(future_map):
            node_id = future_map[future]
            try:
                results_map[node_id] = future.result()
            except Exception as exc:
                results_map[node_id] = {
                    "id": node_id,
                    "latency_ms": 0,
                    "probe_status": "unavailable",
                    "probe_message": f"测试异常: {exc}",
                    "probed_at": time.time(),
                    "owner": "",
                    "asn": "",
                    "as_name": "",
                    "location": "",
                    "ip_type": "",
                    "quality": "",
                }

    successful_nodes = [item for item in results_map.values() if item.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as exc:
            print(f"[批量测速] 补充节点信息失败: {exc}", flush=True)

    with lock:
        current_nodes = read_json(NODES_FILE, [])
        for node in current_nodes:
            node_id = node.get("id")
            if node_id in results_map:
                node.update(results_map[node_id])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        valid_nodes = len([node for node in sorted_nodes if node.get("probe_status") == "available"])
    set_state(last_check_at=time.time(), valid_nodes=valid_nodes)
    return [results_map[node_id] for node_id in node_ids if node_id in results_map]

def schedule_followup_tests(limit: int | None = None) -> None:
    max_nodes = limit if limit is not None else FOLLOWUP_TEST_BATCH_SIZE
    if max_nodes <= 0:
        return
    if not followup_test_lock.acquire(blocking=False):
        return

    def worker() -> None:
        try:
            heavy_task_lock.acquire()
            with lock:
                nodes = read_json(NODES_FILE, [])
                node_ids = [
                    str(node.get("id") or "")
                    for node in nodes
                    if not node.get("active") and node.get("probe_status") == "not_checked"
                ][:max_nodes]
            if not node_ids:
                return
            set_node_testing_state(node_ids, True)
            try:
                test_multiple_nodes(node_ids)
            finally:
                set_node_testing_state(node_ids, False)
        except Exception as exc:
            print(f"[后台续测] 检测待检测节点失败: {exc}", flush=True)
            log_to_json("WARNING", "Main", f"后台续测失败: {exc}")
        finally:
            heavy_task_lock.release()
            followup_test_lock.release()

    threading.Thread(target=worker, daemon=True).start()

def auto_switch_node(attempt: int = 0) -> None:
    global is_connecting
    if attempt >= 3:
        print("[自动切换] 连续切换失败 3 次，停止本轮自动切换", flush=True)
        return

    ui_cfg = load_ui_config()
    if not ui_cfg.get("connection_enabled", True):
        print("[自动切换] 当前已关闭自动连接，不执行切换", flush=True)
        return
    if ui_cfg.get("routing_mode") == "fixed_ip":
        print("[自动切换] 当前是固定节点模式，不执行自动切换", flush=True)
        return

    with lock:
        nodes = read_json(NODES_FILE, [])
    candidates = [node for node in nodes if node.get("probe_status") == "available" and not node.get("active")]
    candidates = filter_nodes_for_routing(candidates, ui_cfg)
    candidates = sort_all_nodes(candidates)

    if not candidates:
        msg = "当前没有可切换的可用节点"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_json(NODES_FILE, [])
            for node in nodes:
                node["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        return

    next_node = candidates[0]
    msg = f"准备自动切换到节点 {next_node['id']}"
    print(f"[自动切换] {msg}", flush=True)
    log_to_json("INFO", "VPN", msg)
    with lock:
        is_connecting = False
    try:
        connect_node(str(next_node["id"]))
    except Exception as exc:
        print(f"[自动切换] 节点 {next_node['id']} 连接失败: {exc}", flush=True)
        log_to_json("WARNING", "VPN", f"自动切换失败: {exc}")
        auto_switch_node(attempt + 1)

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting, proxy_health_failures
    with lock:
        if is_connecting:
            return "已有连接任务正在执行"
        is_connecting = True
        active_openvpn_node_id = node_id
    set_state(
        active_openvpn_node_id=node_id,
        is_connecting=True,
        active_node_latency="正在连接",
        last_check_message="正在初始化连接",
    )

    try:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"未找到节点: {node_id}")

        ui_cfg = load_ui_config()
        allowed_protocols = set(normalize_routing_protocols(ui_cfg.get("routing_protocol", ["udp"])))
        if node_protocol(node) not in allowed_protocols:
            raise RuntimeError("当前协议筛选不允许连接这个节点")

        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")

        set_state(active_node_latency="清理旧连接", last_check_message="正在关闭旧连接")
        stop_active_openvpn()

        set_state(active_node_latency="准备配置", last_check_message="正在准备 OpenVPN 配置")
        config_path = ensure_node_config_path(node)

        set_state(active_node_latency="建立隧道", last_check_message="正在启动 OpenVPN 核心")
        ok, message, process = run_openvpn_until_ready(str(config_path), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            for item in nodes:
                item["active"] = False
                if item.get("id") == node_id:
                    item["probe_status"] = "unavailable"
                    item["probe_message"] = message
            write_json(NODES_FILE, nodes)
            set_state(
                active_openvpn_node_id="",
                is_connecting=False,
                active_node_latency="连接失败",
                last_check_message=f"节点连接失败: {message}",
            )
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)

        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id

        set_state(active_node_latency="配置路由", last_check_message="正在设置策略路由")
        setup_policy_routing("tun0")

        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        try:
            latency = vpn_utils.ping_latency_ms(
                str(node.get("ip") or node.get("remote_host") or ""),
                parse_int(node.get("remote_port")),
                parse_int(node.get("ping")),
            )
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass

        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                item["probe_status"] = "available"
                item["probe_message"] = f"当前正在使用，代理入口: {get_proxy_display_url()}"
                item["latency_ms"] = last_active_latency or item.get("latency_ms", 0)
                item["probed_at"] = time.time()
        write_json(NODES_FILE, nodes)

        set_state(last_check_message="正在检测本地代理出口")
        proxy_result = check_proxy_health()
        if proxy_result["ok"]:
            proxy_health_failures = 0
            set_state(
                proxy_ok=True,
                proxy_ip=proxy_result["ip"],
                proxy_latency_ms=proxy_result["latency_ms"],
                proxy_error="",
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=proxy_result.get("error", "未知错误"),
            )

        latency_text = f"{last_active_latency} ms" if last_active_latency > 0 else "未测出延迟"
        set_state(
            active_openvpn_node_id=node_id,
            is_connecting=False,
            active_node_latency=latency_text,
            last_check_message=f"节点 {node_id} 已连接",
        )
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功")
        schedule_followup_tests(FOLLOWUP_TEST_BATCH_SIZE)
        return f"Connected {node_id}"
    finally:
        with lock:
            is_connecting = False

def maintain_valid_nodes(force: bool = False) -> str:
    global is_connecting
    ensure_dirs()
    if not maintain_job_lock.acquire(blocking=False):
        return "节点维护已在进行中"

    with lock:
        is_connecting = True

    try:
        heavy_task_lock.acquire()
        if force:
            stop_active_openvpn()

        set_state(is_connecting=True, last_check_message="正在抓取最新节点列表")
        try:
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=str(exc))
            return f"抓取节点失败: {exc}"

        with lock:
            old_nodes = read_json(NODES_FILE, [])
            active_node = next((node for node in old_nodes if node.get("active")), None)

        old_by_endpoint = {node_endpoint_key(node): node for node in old_nodes}
        merged_nodes: list[dict[str, Any]] = []
        seen_endpoints: set[tuple[str, int, str]] = set()

        for candidate in candidates:
            key = node_endpoint_key(candidate)
            old_node = old_by_endpoint.get(key)
            merged = merge_node_runtime_fields(candidate, old_node) if old_node else dict(candidate)
            merged["missing_from_latest_fetch"] = False
            merged_nodes.append(merged)
            seen_endpoints.add(key)

        for old_node in old_nodes:
            key = node_endpoint_key(old_node)
            if key in seen_endpoints:
                continue
            if old_node.get("active"):
                kept = dict(old_node)
                kept["missing_from_latest_fetch"] = True
                merged_nodes.append(kept)
                seen_endpoints.add(key)
                continue
            if (
                old_node.get("probe_status") == "available"
                and 0 < parse_int(old_node.get("latency_ms")) <= KEEP_OLD_NODE_LATENCY_MS
            ):
                kept = dict(old_node)
                kept["missing_from_latest_fetch"] = True
                merged_nodes.append(kept)
                seen_endpoints.add(key)

        merged_nodes = sort_all_nodes(merged_nodes)[:MAX_CACHED_NODES]
        write_json(NODES_FILE, merged_nodes)

        to_test = [
            node["id"]
            for node in merged_nodes
            if not node.get("active") and node.get("probe_status") != "available"
        ][:MAX_MAINTAIN_TEST_NODES]

        if to_test:
            set_state(is_connecting=True, last_check_message=f"正在检测 {len(to_test)} 个节点")
            test_multiple_nodes(to_test)

        final_nodes = read_json(NODES_FILE, [])
        valid_nodes_count = len([node for node in final_nodes if node.get("probe_status") == "available"])

        ui_cfg = load_ui_config()
        if ui_cfg.get("connection_enabled", True) and not active_openvpn_running():
            if ui_cfg.get("routing_mode") == "fixed_ip":
                target_id = str(ui_cfg.get("fixed_node_id") or active_openvpn_node_id or "").strip()
                if target_id and any(node.get("id") == target_id for node in final_nodes):
                    with lock:
                        is_connecting = False
                    try:
                        connect_node(target_id)
                    finally:
                        with lock:
                            is_connecting = True
            else:
                filtered_available = filter_nodes_for_routing(
                    [node for node in final_nodes if node.get("probe_status") == "available"],
                    ui_cfg,
                )
                if filtered_available:
                    with lock:
                        is_connecting = False
                    try:
                        auto_switch_node()
                    finally:
                        with lock:
                            is_connecting = True

        message = f"已抓取 {len(candidates)} 个节点，当前可用 {valid_nodes_count} 个"
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            valid_nodes=valid_nodes_count,
            active_openvpn_node_id=active_openvpn_node_id,
            is_connecting=False,
        )
        schedule_followup_tests(FOLLOWUP_TEST_BATCH_SIZE)
        return message
    finally:
        heavy_task_lock.release()
        with lock:
            is_connecting = False
        maintain_job_lock.release()

def run_node_refresh(force: bool = False, disconnect_active: bool = False) -> str:
    global is_connecting
    ensure_dirs()
    if not maintain_job_lock.acquire(blocking=False):
        return "节点维护已在进行中"

    with lock:
        is_connecting = True

    try:
        heavy_task_lock.acquire()
        if force and disconnect_active:
            stop_active_openvpn()

        set_state(is_connecting=True, last_check_message="正在抓取最新节点列表")
        try:
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            failed_at = time.time()
            cooldown_until = failed_at + AUTO_REFRESH_COOLDOWN_SECONDS if not force else 0.0
            message = f"抓取节点失败: {exc}"
            if cooldown_until > 0:
                message += "，自动补抓进入 1 小时冷却"
            set_state(
                last_fetch_at=failed_at,
                last_fetch_status="error",
                last_fetch_message=message,
                last_check_at=failed_at,
                last_check_message=message,
                auto_refresh_completed_at=failed_at,
                auto_refresh_cooldown_until=cooldown_until,
                is_connecting=False,
            )
            return message

        with lock:
            old_nodes = read_json(NODES_FILE, [])

        old_by_endpoint = {node_endpoint_key(node): node for node in old_nodes}
        merged_nodes: list[dict[str, Any]] = []
        seen_endpoints: set[tuple[str, int, str]] = set()

        for candidate in candidates:
            key = node_endpoint_key(candidate)
            old_node = old_by_endpoint.get(key)
            merged = merge_node_runtime_fields(candidate, old_node) if old_node else dict(candidate)
            merged["missing_from_latest_fetch"] = False
            merged_nodes.append(merged)
            seen_endpoints.add(key)

        for old_node in old_nodes:
            key = node_endpoint_key(old_node)
            if key in seen_endpoints:
                continue
            if old_node.get("active"):
                kept = dict(old_node)
                kept["missing_from_latest_fetch"] = True
                merged_nodes.append(kept)
                seen_endpoints.add(key)
                continue
            if (
                old_node.get("probe_status") == "available"
                and 0 < parse_int(old_node.get("latency_ms")) <= KEEP_OLD_NODE_LATENCY_MS
            ):
                kept = dict(old_node)
                kept["missing_from_latest_fetch"] = True
                merged_nodes.append(kept)
                seen_endpoints.add(key)

        merged_nodes = sort_all_nodes(merged_nodes)[:MAX_CACHED_NODES]
        write_json(NODES_FILE, merged_nodes)

        ui_cfg = load_ui_config()
        pending_ids = [
            str(node.get("id") or "")
            for node in filter_nodes_for_routing(merged_nodes, ui_cfg)
            if not node.get("active") and node.get("probe_status") != "available"
        ]

        while pending_ids:
            current_nodes = read_json(NODES_FILE, [])
            routed_valid_nodes = count_available_nodes_for_routing(current_nodes, ui_cfg)
            if routed_valid_nodes >= TARGET_VALID_NODES:
                break
            batch_ids = pending_ids[:MAX_BATCH_TEST_REQUEST_SIZE]
            pending_ids = pending_ids[MAX_BATCH_TEST_REQUEST_SIZE:]
            set_state(is_connecting=True, last_check_message=f"正在检测 {len(batch_ids)} 个节点")
            test_multiple_nodes(batch_ids)

        final_nodes = read_json(NODES_FILE, [])
        valid_nodes_count = len([node for node in final_nodes if node.get("probe_status") == "available"])
        routed_valid_nodes = count_available_nodes_for_routing(final_nodes, ui_cfg)
        refresh_completed_at = time.time()
        cooldown_until = refresh_completed_at + AUTO_REFRESH_COOLDOWN_SECONDS if routed_valid_nodes < TARGET_VALID_NODES else 0.0

        if ui_cfg.get("connection_enabled", True) and not active_openvpn_running():
            if ui_cfg.get("routing_mode") == "fixed_ip":
                target_id = str(ui_cfg.get("fixed_node_id") or active_openvpn_node_id or "").strip()
                if target_id and any(node.get("id") == target_id for node in final_nodes):
                    with lock:
                        is_connecting = False
                    try:
                        connect_node(target_id)
                    finally:
                        with lock:
                            is_connecting = True
            else:
                filtered_available = filter_nodes_for_routing(
                    [node for node in final_nodes if node.get("probe_status") == "available"],
                    ui_cfg,
                )
                if filtered_available:
                    with lock:
                        is_connecting = False
                    try:
                        auto_switch_node()
                    finally:
                        with lock:
                            is_connecting = True

        message = f"已抓取 {len(candidates)} 个节点，当前可用 {valid_nodes_count} 个，当前协议可用 {routed_valid_nodes} 个"
        if cooldown_until > 0:
            message += "，库存不足，进入 1 小时冷却"

        set_state(
            last_fetch_at=refresh_completed_at,
            last_fetch_status="success",
            last_fetch_message=message,
            last_check_at=refresh_completed_at,
            last_check_message=message,
            valid_nodes=valid_nodes_count,
            routed_valid_nodes=routed_valid_nodes,
            auto_refresh_completed_at=refresh_completed_at,
            auto_refresh_cooldown_until=cooldown_until,
            active_openvpn_node_id=active_openvpn_node_id,
            is_connecting=False,
        )
        schedule_followup_tests(FOLLOWUP_TEST_BATCH_SIZE)
        return message
    finally:
        heavy_task_lock.release()
        with lock:
            is_connecting = False
        maintain_job_lock.release()

def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        try:
            current_nodes = read_json(NODES_FILE, [])
            ui_cfg = load_ui_config()
            total_valid_nodes = len([node for node in current_nodes if node.get("probe_status") == "available"])
            routed_valid_nodes = count_available_nodes_for_routing(current_nodes, ui_cfg)
            current_state = get_state()
            if should_run_daily_source_scan(time.time()):
                run_source_scan(force=False)
                continue
            should_refresh, refresh_reason = should_trigger_auto_refresh(current_state, routed_valid_nodes, time.time())
            set_state(
                valid_nodes=total_valid_nodes,
                routed_valid_nodes=routed_valid_nodes,
                last_auto_refresh_reason=refresh_reason if should_refresh else current_state.get("last_auto_refresh_reason", ""),
            )
            if should_refresh:
                run_node_refresh(force=False, disconnect_active=False)
            else:
                schedule_followup_tests()
        except Exception as exc:
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")

        time.sleep(COLLECTOR_DECISION_INTERVAL_SECONDS)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">AimiliVPN</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value.trim();
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";
      
      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });
        
        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AimiliVPN 节点池管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: center;
    }

    button, .btn-telegram {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      white-space: nowrap;
      text-decoration: none;
      box-sizing: border-box;
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-telegram {
      background: rgba(43, 162, 223, 0.15);
      border: 1px solid rgba(43, 162, 223, 0.3);
      color: #2ba2df;
    }

    .btn-telegram:hover {
      background: rgba(43, 162, 223, 0.25);
      border-color: rgba(43, 162, 223, 0.5);
      color: #2ba2df;
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
      line-height: 1.5;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    /* New style additions */
    .header-badge-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      height: 24px;
      box-sizing: border-box;
    }
    .header-badge-link:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--border-color-hover);
      color: var(--text-primary);
      transform: translateY(-1px);
    }
    .flex-row-container {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }
    .flex-row-container > * {
      flex: 1;
      min-width: 320px;
      margin-bottom: 0 !important;
    }
    .vps-promo-tab {
      position: fixed;
      right: 0;
      top: 50%;
      transform: translateY(-50%);
      width: 38px;
      background: var(--primary-gradient);
      border: 1px solid var(--border-color-hover);
      border-right: none;
      border-radius: 8px 0 0 8px;
      padding: 16px 6px;
      color: white;
      font-weight: 700;
      font-size: 13px;
      line-height: 1.4;
      text-align: center;
      cursor: pointer;
      z-index: 999;
      box-shadow: -4px 0 20px rgba(99, 102, 241, 0.3);
      transition: all 0.3s ease;
      writing-mode: vertical-rl;
      text-orientation: mixed;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
    }
    .vps-promo-tab:hover {
      padding-right: 10px;
      box-shadow: -4px 0 25px rgba(99, 102, 241, 0.5);
    }

    .ad-section {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 24px;
    }
    
    .ad-card {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    
    .ad-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .ad-badge {
      background: var(--primary-gradient);
      color: white;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 6px;
      font-weight: 700;
      text-transform: uppercase;
      box-shadow: 0 2px 6px rgba(99, 102, 241, 0.3);
    }
    
    .ad-links {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }
    
    .ad-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      justify-content: space-between;
      transition: all 0.2s ease;
    }
    
    .ad-item:hover {
      background: rgba(255, 255, 255, 0.04);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
    }
    
    .ad-tag {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 6px;
      width: fit-content;
    }
    
    .tag-normal {
      background: rgba(99, 102, 241, 0.15);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.2);
    }
    
    .tag-opt {
      background: rgba(245, 158, 11, 0.15);
      color: #fde047;
      border: 1px solid rgba(245, 158, 11, 0.2);
    }
    
    .tag-premium {
      background: rgba(16, 185, 129, 0.15);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.2);
    }
    
    .ad-desc {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.5;
      flex: 1;
    }
    
    .ad-btn {
      align-self: flex-start;
      text-decoration: none;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 6px;
      transition: all 0.2s ease;
      text-align: center;
    }
    
    .ad-item:hover .ad-btn {
      background: var(--primary-gradient);
      border-color: transparent;
      color: white;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.2);
    }
    
    .ad-footer {
      border-top: 1px dashed rgba(255, 255, 255, 0.08);
      padding-top: 12px;
      font-size: 13px;
      color: var(--text-secondary);
      text-align: center;
    }
    
    .forum-link {
      color: #818cf8;
      font-weight: 700;
      text-decoration: none;
      transition: color 0.2s ease;
    }
    
    .forum-link:hover {
      color: #a5b4fc;
      text-decoration: underline;
    }

    .toolbar {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .routing-select-wrapper {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      width: fit-content;
      max-width: 100%;
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--border-color);
      padding: 0 12px;
      border-radius: 8px;
      font-size: 13px;
      height: 38px;
      flex: 0 0 auto;
    }

    .routing-select-wrapper select {
      width: auto;
      min-width: 0;
      max-width: 140px;
      height: 30px;
      background: transparent;
      border: none;
      color: var(--text-primary);
      outline: none;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      padding: 0 18px 0 0;
      box-shadow: none;
      white-space: nowrap;
      text-overflow: ellipsis;
      overflow: hidden;
      appearance: none;
    }

    .routing-select-wrapper select:focus {
      border: none;
      box-shadow: none;
      background: transparent;
    }

    #header_routing_country {
      width: 92px;
    }

    #header_routing_ip_type {
      width: 96px;
    }

    .protocol-filter-group {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      height: 42px;
      padding: 0 10px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 500;
      flex: 0 0 auto;
      white-space: nowrap;
    }

    .protocol-filter-title {
      color: var(--text-secondary);
      font-weight: 500;
      margin-right: 2px;
    }

    .protocol-toggle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 46px;
      height: 28px;
      padding: 0 10px;
      border-radius: 999px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      background: rgba(255, 255, 255, 0.03);
      color: var(--text-secondary);
      cursor: pointer;
      font-weight: 700;
      font-size: 12px;
      transition: all 0.2s ease;
      box-sizing: border-box;
    }

    .protocol-toggle[data-proto="tcp"].active {
      background: rgba(96, 165, 250, 0.14);
      color: #93c5fd;
      border-color: rgba(96, 165, 250, 0.3);
      box-shadow: inset 0 0 0 1px rgba(96, 165, 250, 0.1);
    }

    .protocol-toggle[data-proto="udp"].active {
      background: rgba(52, 211, 153, 0.14);
      color: #6ee7b7;
      border-color: rgba(52, 211, 153, 0.28);
      box-shadow: inset 0 0 0 1px rgba(52, 211, 153, 0.08);
    }

    .protocol-toggle:hover {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-primary);
    }

    .protocol-toggle[data-proto="tcp"].active:hover {
      background: rgba(96, 165, 250, 0.2);
      color: #bfdbfe;
    }

    .protocol-toggle[data-proto="udp"].active:hover {
      background: rgba(52, 211, 153, 0.18);
      color: #86efac;
    }

    .proto-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 48px;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.3px;
      border: 1px solid transparent;
      white-space: nowrap;
    }

    .nowrap-cell {
      white-space: nowrap;
    }

    .proto-badge.tcp {
      background: rgba(96, 165, 250, 0.12);
      color: #93c5fd;
      border-color: rgba(96, 165, 250, 0.24);
    }

    .proto-badge.udp {
      background: rgba(52, 211, 153, 0.12);
      color: #6ee7b7;
      border-color: rgba(52, 211, 153, 0.24);
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      min-width: 1320px;
    }

    th, td {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
      vertical-align: middle;
      line-height: 1.45;
      white-space: normal;
      word-break: keep-all;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
      white-space: nowrap;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      white-space: nowrap;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
      line-height: 1;
    }

    .latency-cell {
      white-space: nowrap;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button, .btn-group .btn-telegram {
        flex: 1;
      }
      .btn-group .dropdown {
        flex: 1;
        display: flex;
      }
      .btn-group .dropdown button {
        width: 100%;
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }
    
    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .source-modal-content {
      width: min(75vw, 1200px);
      max-width: min(75vw, 1200px);
      min-width: min(960px, calc(100vw - 32px));
      padding: 28px 30px 30px;
    }
    .source-toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-bottom: 14px;
    }
    .source-toolbar .input-field {
      flex: 1 1 420px;
      min-width: 280px;
    }
    .source-summary {
      display: flex;
      flex-wrap: wrap;
      gap: 12px 18px;
      margin-bottom: 16px;
      font-size: 13px;
      color: var(--text-secondary);
    }
    .source-table-shell {
      margin-bottom: 0;
    }
    .source-table-container {
      max-height: 58vh;
      overflow: auto;
    }
    .source-table {
      width: 100%;
      min-width: 0;
      table-layout: fixed;
    }
    .source-table th,
    .source-table td {
      padding: 14px 14px;
      vertical-align: middle;
    }
    .source-table th {
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .source-table th.source-col-status,
    .source-table td.source-col-status {
      width: 90px;
    }
    .source-table th.source-col-type,
    .source-table td.source-col-type {
      width: 78px;
    }
    .source-table th.source-col-address,
    .source-table td.source-col-address {
      width: auto;
    }
    .source-table th.source-col-enabled,
    .source-table td.source-col-enabled {
      width: 84px;
      text-align: center;
    }
    .source-table th.source-col-failed,
    .source-table td.source-col-failed {
      width: 76px;
      text-align: center;
    }
    .source-table th.source-col-actions,
    .source-table td.source-col-actions {
      width: 196px;
      text-align: center;
    }
    .source-url-cell {
      min-width: 0;
      padding-right: 8px;
    }
    .source-url-main {
      font-size: 12px;
      line-height: 1.55;
      word-break: break-all;
      color: var(--text-primary);
    }
    .source-url-meta {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 4px;
      line-height: 1.5;
      word-break: break-word;
    }
    .source-checkbox-wrap {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      cursor: pointer;
    }
    .source-checkbox-wrap input {
      accent-color: #22c55e;
    }
    .source-failure-count {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .source-actions {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .source-test-btn {
      min-width: 72px;
      height: 34px;
      padding: 0 12px;
      border-radius: 8px;
      border: 1px solid rgba(99, 102, 241, 0.25);
      background: rgba(99, 102, 241, 0.14);
      color: #c7d2fe;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .source-test-btn:hover:not(:disabled) {
      background: rgba(99, 102, 241, 0.24);
      border-color: rgba(129, 140, 248, 0.5);
      color: #e0e7ff;
    }
    .source-test-btn:disabled {
      opacity: 0.55;
      cursor: not-allowed;
    }
    @media (max-width: 1100px) {
      .source-modal-content {
        width: calc(100vw - 24px);
        max-width: calc(100vw - 24px);
        min-width: 0;
        padding: 24px 18px;
      }
      .source-table {
        min-width: 940px;
      }
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }
    select option {
      background-color: #0f172a;
      color: #f8fafc;
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      AimiliVPN 节点管理系统
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">
    <div class="routing-select-wrapper">
      <label for="header_routing_country" style="color: var(--text-secondary); font-weight: 500; white-space: nowrap;">出站国家:</label>
      <select id="header_routing_country">
        <option value="">全部</option>
      </select>
    </div>
    <div class="routing-select-wrapper">
      <label for="header_routing_ip_type" style="color: var(--text-secondary); font-weight: 500; white-space: nowrap;">IP类型:</label>
      <select id="header_routing_ip_type">
        <option value="all">全部IP</option>
        <option value="residential">仅静态住宅IP</option>
        <option value="hosting">仅机房IP</option>
      </select>
    </div>
    <div class="routing-select-wrapper">
      <span style="color: var(--text-secondary); font-weight: 500; white-space: nowrap;">协议:</span>
      <label style="display: inline-flex; align-items: center; gap: 4px; cursor: pointer; color: var(--text-primary);">
        <input type="checkbox" id="header_protocol_tcp" value="tcp" style="accent-color: #22c55e;">
        <span>TCP</span>
      </label>
      <label style="display: inline-flex; align-items: center; gap: 4px; cursor: pointer; color: var(--text-primary);">
        <input type="checkbox" id="header_protocol_udp" value="udp" style="accent-color: #22c55e;">
        <span>UDP</span>
      </label>
    </div>
    <div class="dropdown">
      <button id="github_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GITHUB
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="github_dropdown" class="dropdown-content">
        <a href="https://github.com/baoweise-bot/aimili-vpngate" target="_blank">正式版</a>
        <a href="https://github.com/baoweise-bot/aimili-vpngate/tree/bate" target="_blank">测试版</a>
      </div>
    </div>
    <a href="https://t.me/arestemple" target="_blank" class="btn-telegram">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336-.063.065-.129.13-.19.193-.34.347-.597.609-.043.974.265.175.474.319.684.457.228.15.457.301.765.503.074.049.143.098.207.143.297.206.58.404.916.373.195-.018.398-.2.502-.754.25-1.332.74-4.22.842-5.281.01-.088.001-.22-.103-.312-.104-.092-.252-.09-.323-.087a1.52 1.52 0 0 0-.254.04z"/></svg>
      Telegram
    </a>
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          账号密码设置
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理及网络设置
        </a>
        <a href="javascript:void(0)" onclick="openSourceModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 7h16M4 12h16M4 17h16" /></svg>
          API源管理
        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>
  <main>
  
    <section class="stats">
      <div class="stat">
        <div class="stat-info">
          <strong id="total">0</strong>
          <span>全网备选节点总数</span>
        </div>
        <div class="stat-icon-wrapper">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
        </div>
      </div>
      <div class="stat">
        <div class="stat-info">
          <strong id="target">3</strong>
          <span>目标优选节点数</span>
        </div>
        <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.2);">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--warning);"><path stroke-linecap="round" stroke-linejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
        </div>
      </div>
      <div class="stat">
        <div class="stat-info">
          <strong id="active">0</strong>
          <span>当前活动连接数</span>
        </div>
        <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.2);">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--success);"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
        </div>
      </div>
    </section>

    <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
      </section>



  <section class="toolbar">
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
    </select>
    <div class="protocol-filter-group">
      <span class="protocol-filter-title">展示协议</span>
      <button type="button" id="list_protocol_tcp" class="protocol-toggle active" data-proto="tcp">TCP</button>
      <button type="button" id="list_protocol_udp" class="protocol-toggle active" data-proto="udp">UDP</button>
    </div>
    <input id="search" placeholder="输入国家、位置、IP、ASN、运营主体等过滤节点..." />
    <button id="btn_batch_test" class="btn-primary" style="height: 42px; padding: 0 20px; font-weight: 600; background: var(--primary-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      批量测试本页
    </button>
    <button id="btn_batch_test_all" class="btn-primary" style="height: 42px; padding: 0 20px; font-weight: 600; background: var(--success-gradient); margin-left: 12px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      批量测试全部
    </button>
  </section>
  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 110px;">状态</th>
            <th style="width: 92px;">延迟</th>
            <th style="width: 220px;">IP 地址 : 端口</th>
            <th style="width: 220px;">物理位置</th>
            <th style="width: 220px;">ASN</th>
            <th style="width: 180px;">运营主体 / ISP</th>
            <th style="width: 90px;">协议</th>
            <th style="width: 110px;">网络质量</th>
            <th style="width: 110px;">IP 类型</th>
            <th style="width: 160px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (账号密码设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          账号密码设置
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="cred_username">新管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入新管理账号">
        </div>
        
        <div class="form-group" style="margin-bottom: 24px;">
          <label class="form-label" for="cred_password">新安全密码</label>
          <input type="password" id="cred_password" class="input-field" required placeholder="请输入新安全密码">
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理与网络设置
        </h3>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="net_port">网页管理端口</label>
          <input type="number" id="net_port" class="input-field" required min="1" max="65535" placeholder="8787">
        </div>
        
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="net_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="net_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>

        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <div class="form-group" style="margin-bottom: 12px; margin-top: 16px;">
          <label class="form-label" for="net_proxy_user">SOCKS5 代理账号 (留空则不验证)</label>
          <input type="text" id="net_proxy_user" class="input-field" placeholder="请输入代理连接账号">
        </div>

        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_pass">SOCKS5 代理密码 (留空则不验证)</label>
          <input type="text" id="net_proxy_pass" class="input-field" placeholder="请输入代理连接密码">
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="net_routing_mode">IP 出站路由模式</label>
            <select id="net_routing_mode" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;" onchange="handleRoutingModeChange(this.value)">
              <option value="auto">自动配置 (智能切换，最稳定)</option>
              <option value="fixed_ip">固定 IP (永不自动换 IP)</option>
              <option value="fixed_region">固定地区 (锁定特定国家节点)</option>
            </select>
          </div>
          
          <div id="net_force_country_group" class="form-group" style="margin-bottom: 12px; display: none;">
            <label class="form-label" for="net_force_country">锁定国家地区</label>
            <select id="net_force_country" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">正在加载节点国家...</option>
            </select>
          </div>
          
          <div id="net_routing_warning" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Ad Modal (VPS 购买推荐) -->
  <div id="ad_modal" class="modal">
    <div class="modal-content" style="max-width: 640px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--warning);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.663 17h4.673M12 3v1m6.364.364l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /></svg>
          VPS 购买推荐
        </h3>
        <button type="button" onclick="closeAdModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div class="ad-links" style="grid-template-columns: 1fr; gap: 16px;">
        <div class="ad-item">
          <span class="ad-tag tag-normal">普通用户推荐</span>
          <span class="ad-desc">RackNerd - 超低折扣价格，日常使用实惠方便，海外多机房可选，推荐普通家庭或低频用户。</span>
          <a href="https://my.racknerd.com/aff.php?aff=18708" target="_blank" class="ad-btn">点击进入官网</a>
        </div>
        <div class="ad-item">
          <span class="ad-tag tag-opt">网络优化推荐</span>
          <span class="ad-desc">VMiss - 专线优化网络 (CN2 GIA/9929/CMIN2 等顶级线路)，低延迟不丢包，推荐高网络要求用户。</span>
          <a href="https://app.vmiss.com/aff.php?aff=4619" target="_blank" class="ad-btn">点击进入官网</a>
        </div>
        <div class="ad-item">
          <span class="ad-tag tag-premium">高端企业推荐</span>
          <span class="ad-desc">BandwagonHost (搬瓦工) - 直连三网顶级专线，经典高带宽 CN2 GIA 线路，超凡稳定速度。</span>
          <a href="https://bandwagonhost.com/aff.php?aff=81790" target="_blank" class="ad-btn">点击进入官网</a>
        </div>
      </div>
      
      <div class="ad-footer" style="margin-top: 20px;">
        官方技术支持及优质资源交流论坛：<a href="https://339936.xyz" target="_blank" class="forum-link">339936.xyz</a>
      </div>

      <div class="ad-footer" style="margin-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px; text-align: left; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
        <div style="font-weight: bold; color: var(--text-primary); margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          🎁 捐赠支持项目开发：
        </div>
        <div style="font-family: monospace; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 6px; margin-top: 6px; word-break: break-all; select-all: true;">
          <span style="color: var(--primary); font-weight: bold;">BNB (BSC):</span> 0xB6d78c42CEB0687A31B8cfEBE4b51b6eB8953C17<br>
          <span style="color: var(--primary); font-weight: bold;">TRX (TRC20):</span> TSdzCW6JvsrqcppodYjhSrku4mYmDJ9pxf
        </div>
      </div>
    </div>
  </div>

  <div class="vps-promo-tab" onclick="openAdModal()">VPS购买推荐</div>

  <!-- Source Modal (API 源管理) -->
  <div id="source_modal" class="modal">
    <div class="modal-content source-modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 7h16M4 12h16M4 17h16" /></svg>
          API 源管理
        </h3>
        <button type="button" onclick="closeSourceModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div id="source_error" style="display: none; color: var(--danger); font-size: 13px; margin-bottom: 14px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 8px;"></div>
      <div id="source_success" style="display: none; color: var(--success); font-size: 13px; margin-bottom: 14px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 8px;"></div>

      <div class="source-toolbar">
        <input id="source_add_input" class="input-field" placeholder="输入手动源地址，支持域名或完整 api/iphone/ 地址">
        <button id="source_add_btn" type="button" class="btn-primary" style="height: 40px; padding: 0 18px;">添加手动源</button>
        <button id="source_scan_btn" type="button" class="btn-primary" style="height: 40px; padding: 0 18px; background: var(--success-gradient);">立即扫描</button>
      </div>

      <div class="source-summary">
        <div>源总数: <strong id="source_total_count_text" style="color: var(--text-primary);">0</strong></div>
        <div>健康源: <strong id="source_healthy_count_text" style="color: var(--text-primary);">0</strong></div>
        <div>最近扫描: <strong id="source_last_scan_time_text" style="color: var(--text-primary);">从未</strong></div>
      </div>

      <div id="source_last_scan_message" style="margin-bottom: 14px; padding: 10px 12px; border-radius: 8px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); color: var(--text-secondary); font-size: 13px;">
        暂无扫描记录
      </div>

      <div class="table-wrapper source-table-shell">
        <div class="table-container source-table-container">
          <table class="source-table">
            <thead>
              <tr>
                <th class="source-col-status">状态</th>
                <th class="source-col-type">类型</th>
                <th class="source-col-address">地址</th>
                <th class="source-col-enabled">启用</th>
                <th class="source-col-failed">失败</th>
                <th class="source-col-actions">操作</th>
              </tr>
            </thead>
            <tbody id="source_rows">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 20px 0;">正在加载源列表...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content" style="max-width: 600px; width: 90%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关运行状态与自检
        </h3>
        <button type="button" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed rgba(255, 255, 255, 0.08); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>
        
        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>
      
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>
        
        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: rgba(255, 255, 255, 0.03);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
        </div>
        
        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #a5b4fc; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
          <button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
            一键复制
          </button>
          <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 15;
let currentPageNodes = [];
let sourcePool = null;
let sourcePollInterval = null;
let sourceProbePending = new Set();

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function getCountryCountMap() {
  const countMap = {};
  nodes.forEach(n => {
    if (n && n.country) {
      countMap[n.country] = (countMap[n.country] || 0) + 1;
    }
  });
  return countMap;
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countMap = getCountryCountMap();
  const countries = Object.keys(countMap).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  const currentTexts = Array.from(select.options).filter(o => o.value).map(o => o.textContent || "");
  const nextTexts = countries.map(c => `${c} (${countMap[c]})`);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions) &&
      JSON.stringify(nextTexts) === JSON.stringify(currentTexts)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)} (${countMap[c]})</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function normalizeProtoLabel(proto) {
  const value = String(proto || "").toLowerCase();
  if (value.startsWith("tcp")) return "tcp";
  if (value === "udp") return "udp";
  return "";
}

function formatProtoLabel(proto) {
  const value = normalizeProtoLabel(proto);
  if (value === "tcp") return "TCP";
  if (value === "udp") return "UDP";
  return "-";
}

function setProtocolToggleState(button, enabled) {
  if (!button) return;
  button.classList.toggle("active", !!enabled);
  button.setAttribute("aria-pressed", enabled ? "true" : "false");
}

function getNodeSyncPaused() {
  return Boolean(state?.is_connecting) || Boolean(testingNodeIds?.size);
}

async function syncNodes(options = {}) {
  const { renderAfter = true, updateFilters = true } = options;
  const response = await fetch("./api/nodes");
  const data = await response.json();
  nodes = data.nodes || [];
  state = data.state || {};
  stableSortNodes();
  if (updateFilters) {
    updateCountryFilter();
    updateHeaderRoutingControls();
  }
  if (renderAfter) {
    render();
  }
  return data;
}

function getListDisplayProtocols() {
  const selected = [];
  if ($("list_protocol_tcp")?.classList.contains("active")) selected.push("tcp");
  if ($("list_protocol_udp")?.classList.contains("active")) selected.push("udp");
  return selected;
}

function handleListProtocolFilterChange(event) {
  const button = event?.currentTarget;
  if (!button) return;
  const nextActive = !button.classList.contains("active");
  if (!nextActive && getListDisplayProtocols().length <= 1) {
    alert("列表展示请至少保留一种协议");
    return;
  }
  setProtocolToggleState(button, nextActive);
  currentPage = 1;
  render();
}

function getFilteredNodes() {
  const q = $("search").value.toLowerCase();
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  const selectedProtocols = getListDisplayProtocols();
  return nodes.filter(n => {
    if (!n) return false;
    if (selectedCountry && n.country !== selectedCountry) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
    }
    if (selectedProtocols.length > 0) {
      const proto = normalizeProtoLabel(n.proto);
      if (!selectedProtocols.includes(proto)) {
        return false;
      }
    }
    const searchStr = [
      n.country || "", n.country_short || "", n.ip || "", n.remote_host || "", n.proto || "",
      translateQuality(n.quality), translateIpType(n.ip_type), n.location || "", n.owner || "", n.as_name || ""
    ].join(" ").toLowerCase();
    return searchStr.includes(q);
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const getStatusRank = node => {
      if (node.active) return 0;
      if (node.probe_status === "available") return 1;
      if (node.probe_status === "not_checked") return 2;
      if (node.probe_status === "unavailable") return 3;
      return 4;
    };
    const getLatency = node => {
      const latency = Number.parseInt(node.latency_ms, 10);
      return Number.isFinite(latency) && latency >= 0 ? latency : 999999;
    };
    const aStatusRank = getStatusRank(a);
    const bStatusRank = getStatusRank(b);
    if (aStatusRank !== bStatusRank) {
      return aStatusRank - bStatusRank;
    }
    const aLatency = getLatency(a);
    const bLatency = getLatency(b);
    if (aLatency !== bLatency) {
      return aLatency - bLatency;
    }
    const aScore = Number.parseInt(a.score, 10) || 0;
    const bScore = Number.parseInt(b.score, 10) || 0;
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n && (n.active || n.id === activeNodeId));
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting && !activeNode) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    const activeProto = formatProtoLabel(activeNode.proto);
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
              <span style="margin-left: 12px;">协议: <strong><span class="proto-badge ${esc(normalizeProtoLabel(activeNode.proto) || "udp")}">${esc(activeProto)}</span></strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  
  if ($("total")) $("total").textContent = nodes.length; 
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms}&nbsp;ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      const protoClass = normalizeProtoLabel(n.proto) || "udp";
      const protoText = formatProtoLabel(n.proto);
      
      const isTesting = testingNodeIds.has(n.id) || Boolean(n.is_testing);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;
      
      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="latency-cell">${latencyText}</td>
        <td class="mono nowrap-cell">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td>${esc(displayLocation)}</td>
        <td class="mono" style="font-size:12px; color:var(--text-primary);">${esc(n.asn||"-")}</td>
        <td>${esc(n.owner||n.as_name||"-")}</td>
        <td><span class="proto-badge ${esc(protoClass)}">${esc(protoText)}</span></td>
        <td class="nowrap-cell">${esc(translateQuality(n.quality))}</td>
        <td class="nowrap-cell">${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${testBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    try {
      await syncNodes();
    } catch (syncError) {
      render();
    }
  }
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      await syncNodes();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}

// Batch test button implementation
$("btn_batch_test").onclick = async () => {
  const pageNodes = currentPageNodes || [];
  if (pageNodes.length === 0) {
    alert("当前页面没有可供测试的备选节点");
    return;
  }
  
  const btn = $("btn_batch_test");
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width: 14px; height: 14px; display: inline-block; margin-right: 6px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>测试中...`;
  
  pageNodes.forEach(n => testingNodeIds.add(n.id));
  render();
  
  const testPromises = pageNodes.map(async (n) => {
    const id = n.id;
    try {
      const response = await fetch("./api/test_node", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
      });
      const result = await response.json();
      if (result.ok && result.node) {
        const idx = nodes.findIndex(item => item.id === id);
        if (idx !== -1) {
          nodes[idx] = result.node;
        }
      }
    } catch (e) {
    } finally {
      testingNodeIds.delete(id);
      render();
    }
  });
  
  try {
    await Promise.all(testPromises);
  } catch (e) {
  } finally {
    try {
      await syncNodes();
    } catch (syncError) {
      render();
    }
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 批量测试本页`;
  }
};

// ==========================================
// 新增：批量测试所有获取到节点的实现逻辑
// ==========================================
$("btn_batch_test_all").onclick = async () => {
  const filteredNodes = getFilteredNodes();
  const filteredIds = filteredNodes.map(node => node.id).filter(Boolean);
  if (filteredIds.length === 0) {
    alert("当前筛选结果里没有可测试的节点。");
    return;
  }

  const btn = $("btn_batch_test_all");
  const originalHtml = btn.innerHTML;
  const chunkSize = 50;

  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width: 14px; height: 14px; display: inline-block; margin-right: 6px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>测试筛选节点中...`;

  filteredIds.forEach(id => testingNodeIds.add(id));
  render();

  try {
    for (let i = 0; i < filteredIds.length; i += chunkSize) {
      const chunkIds = filteredIds.slice(i, i + chunkSize);
      try {
        const response = await fetch("./api/test_nodes", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: chunkIds })
        });
        const result = await response.json();

        if (result.ok && Array.isArray(result.nodes)) {
          result.nodes.forEach(updatedNode => {
            const idx = nodes.findIndex(item => item.id === updatedNode.id);
            if (idx !== -1) {
              nodes[idx] = updatedNode;
            }
          });
        }
      } catch (e) {
        console.error("批量测试筛选节点失败:", e);
      } finally {
        chunkIds.forEach(id => testingNodeIds.delete(id));
        render();
      }
    }
  } finally {
    try {
      await syncNodes();
    } catch (syncError) {
      render();
    }
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
};

function updateHeaderRoutingControls() {
  const selectCountry = $("header_routing_country");
  const selectIpType = $("header_routing_ip_type");
  const protocolTcp = $("header_protocol_tcp");
  const protocolUdp = $("header_protocol_udp");
  if (!selectCountry || !selectIpType || !protocolTcp || !protocolUdp) return;
  
  // 1. Countries list
  const countMap = getCountryCountMap();
  const countries = Object.keys(countMap).sort();
  const currentOptions = Array.from(selectCountry.options).map(o => o.value).filter(v => v && v !== "fixed_ip_mode");
  const currentTexts = Array.from(selectCountry.options)
    .filter(o => o.value && o.value !== "fixed_ip_mode")
    .map(o => o.textContent || "");
  const nextTexts = countries.map(c => c);
  
  const rebuild = JSON.stringify(countries) !== JSON.stringify(currentOptions) ||
    JSON.stringify(nextTexts) !== JSON.stringify(currentTexts);
  if (rebuild) {
    selectCountry.innerHTML = '<option value="">全部</option>' + 
      countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  }
  
  // 2. Set value
  if (state.routing_mode === "fixed_ip") {
    if (!selectCountry.querySelector('option[value="fixed_ip_mode"]')) {
      const opt = document.createElement("option");
      opt.value = "fixed_ip_mode";
      opt.textContent = "固定 IP 模式";
      opt.disabled = true;
      selectCountry.appendChild(opt);
    }
    selectCountry.value = "fixed_ip_mode";
  } else if (state.routing_mode === "fixed_region") {
    selectCountry.value = state.force_country || "";
  } else {
    selectCountry.value = "";
  }
  
  if (state.routing_mode !== "fixed_ip") {
    const fixedIpOpt = selectCountry.querySelector('option[value="fixed_ip_mode"]');
    if (fixedIpOpt) {
      fixedIpOpt.remove();
    }
  }
  
  selectIpType.value = state.routing_ip_type || "all";
  const enabledProtocols = Array.isArray(state.routing_protocol) ? state.routing_protocol : [];
  protocolTcp.checked = enabledProtocols.includes("tcp");
  protocolUdp.checked = enabledProtocols.includes("udp");
  protocolTcp.parentElement.style.opacity = protocolTcp.checked ? "1" : "0.72";
  protocolUdp.parentElement.style.opacity = protocolUdp.checked ? "1" : "0.72";
}

async function saveHeaderRouting() {
  const selectCountry = $("header_routing_country");
  const selectIpType = $("header_routing_ip_type");
  const protocolTcp = $("header_protocol_tcp");
  const protocolUdp = $("header_protocol_udp");
  
  let routingMode = "auto";
  let forceCountry = selectCountry.value;
  
  if (forceCountry === "fixed_ip_mode") {
    routingMode = "fixed_ip";
    forceCountry = state.force_country || "";
  } else if (forceCountry) {
    routingMode = "fixed_region";
  } else {
    routingMode = "auto";
  }
  
  const routingIpType = selectIpType.value;
  const routingProtocol = [];
  if (protocolTcp && protocolTcp.checked) routingProtocol.push("tcp");
  if (protocolUdp && protocolUdp.checked) routingProtocol.push("udp");
  if (routingProtocol.length === 0) {
    alert("请至少勾选一种协议");
    updateHeaderRoutingControls();
    return;
  }
  
  try {
    const response = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType,
        routing_protocol: routingProtocol
      })
    });
    const result = await response.json();
    if (result.ok) {
      load();
    } else {
      alert("更新路由失败: " + result.error);
    }
  } catch (e) {
    alert("更新出站路由网络请求失败");
  }
}

async function load(){
  await syncNodes();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}

$("search").oninput=()=>{ currentPage = 1; render(); };
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };
$("list_protocol_tcp").onclick = handleListProtocolFilterChange;
$("list_protocol_udp").onclick = handleListProtocolFilterChange;
$("header_routing_country").onchange = saveHeaderRouting;
$("header_routing_ip_type").onchange = saveHeaderRouting;
$("header_protocol_tcp").onchange = saveHeaderRouting;
$("header_protocol_udp").onchange = saveHeaderRouting;

$("refresh").onclick=async()=>{ 
  $("refresh").disabled=true; 
  $("refresh").textContent="正在后台更新..."; 
  try{await fetch("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="更新节点";
  }, 3000);
};
$("source_add_btn").onclick = addSource;
$("source_scan_btn").onclick = triggerSourceScan;
$("source_add_input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    addSource();
  }
});
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle & GitHub dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
const githubBtn = $("github_btn");
const githubDropdown = $("github_dropdown");

if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
    if (githubDropdown) githubDropdown.style.display = "none";
  };
}

if (githubBtn && githubDropdown) {
  githubBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = githubDropdown.style.display === "block";
    githubDropdown.style.display = isShow ? "none" : "block";
    if (adminDropdown) adminDropdown.style.display = "none";
  };
}

document.addEventListener("click", () => {
  if (adminDropdown) adminDropdown.style.display = "none";
  if (githubDropdown) githubDropdown.style.display = "none";
});

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");
  
  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定地区</strong>：限制仅连接选定国家的节点，且后台仅并发测速该国家的节点。如果该国的所有可用节点都失效，会造成代理中断且<strong>绝不自动切换到其他国家</strong>的节点。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "rgba(255, 255, 255, 0.02)";
    warningDiv.style.border = "1px solid rgba(255, 255, 255, 0.05)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    if (n.country) {
      countMap[n.country] = (countMap[n.country] || 0) + 1;
    }
  });
  
  const countries = Object.keys(countMap).sort();
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}个节点)</option>`;
  });
  select.innerHTML = html;
  
  if (state) {
    const mode = state.routing_mode || "auto";
    const modeSelect = $("net_routing_mode");
    if (modeSelect) modeSelect.value = mode;
    select.value = state.force_country || "";
    handleRoutingModeChange(mode);
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
  }
  $("credentials_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  
  if (!username || !password) {
    errorDivEl.textContent = "用户名和密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      successDiv.textContent = "账号密码保存成功，已即时生效！";
      successDiv.style.display = "block";
      setTimeout(() => {
        closeCredentialsModal();
        load();
      }, 1500);
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();
  
  if (state) {
    $("net_port").value = state.port || 8787;
    $("net_suffix").value = state.secret_path || "";
    $("net_proxy_port").value = state.proxy_port || 7928;
    $("net_proxy_user").value = state.proxy_user || ""; // 新增这一行
    $("net_proxy_pass").value = state.proxy_pass || ""; // 新增这一行
  }
  
  populateRoutingCountries();
  $("network_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

function setSourceBanner(kind, message) {
  const errorBox = $("source_error");
  const successBox = $("source_success");
  if (!errorBox || !successBox) return;
  errorBox.style.display = "none";
  successBox.style.display = "none";
  if (!message) return;
  const target = kind === "error" ? errorBox : successBox;
  target.textContent = message;
  target.style.display = "block";
}

function sourceTypeText(type) {
  const dict = { system: "系统", manual: "手动", mirror: "镜像" };
  return dict[type] || "未知";
}

function sourceStatusBadge(item) {
  if (item?.healthy) return { className: "available", text: "可用" };
  if ((item?.status || "") === "待扫描") return { className: "not_checked", text: "待扫描" };
  return { className: "unavailable", text: "不可用" };
}

function setSourceActionBusy(busy) {
  const scanBtn = $("source_scan_btn");
  const addBtn = $("source_add_btn");
  const addInput = $("source_add_input");
  if (scanBtn) scanBtn.disabled = !!busy;
  if (addBtn) addBtn.disabled = !!busy;
  if (addInput) addInput.disabled = !!busy;
}

async function readSourceJsonResponse(res, fallbackMessage) {
  const rawText = await res.text();
  if (!rawText.trim()) {
    throw new Error(fallbackMessage || "服务器返回了空响应，请稍后重试");
  }
  try {
    return JSON.parse(rawText);
  } catch (err) {
    throw new Error(fallbackMessage || "服务器返回的数据不完整，请稍后重试");
  }
}

function renderSources() {
  const rows = $("source_rows");
  if (!rows) return;
  const sources = sourcePool?.sources || [];
  const scanRunning = Boolean(sourcePool?.scan_running);
  const healthyCount = sources.filter(item => item && item.healthy).length;

  $("source_total_count_text").textContent = String(sources.length);
  $("source_healthy_count_text").textContent = String(healthyCount);
  $("source_last_scan_time_text").textContent = time(sourcePool?.last_scan_at || 0);
  $("source_last_scan_message").textContent = sourcePool?.last_scan_message || "暂无扫描记录";

  const scanBtn = $("source_scan_btn");
  if (scanBtn) {
    scanBtn.disabled = scanRunning;
    scanBtn.textContent = scanRunning ? "扫描中..." : "立即扫描";
  }

  if (!sources.length) {
    rows.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-secondary); padding: 20px 0;">当前还没有可管理的源</td></tr>`;
    return;
  }

  rows.innerHTML = sources.map(item => {
    const badge = sourceStatusBadge(item);
    const url = String(item?.url || "");
    const urlToken = encodeURIComponent(url);
    const isProbePending = sourceProbePending.has(url);
    const details = [];
    if (item?.last_http_code) details.push(`HTTP ${item.last_http_code}`);
    if (item?.last_error) details.push(item.last_error);
    if (item?.last_checked_at) details.push(`检测 ${time(item.last_checked_at)}`);
    const detailText = details.length ? `<div class="source-url-meta">${esc(details.join(" · "))}</div>` : "";
    const scanBtnText = isProbePending ? `<span class="badge-pulse"></span>检测中` : "检测";
    const scanBtn = `<button type="button" class="source-test-btn" ${scanRunning || isProbePending ? "disabled" : ""} onclick="probeSource('${urlToken}')">${scanBtnText}</button>`;
    const deleteBtn = `<button type="button" class="connect-btn" style="border-color: rgba(244,63,94,0.35); color: #fecdd3;" onclick="deleteSource('${urlToken}')">删除</button>`;

    return `
      <tr>
        <td class="source-col-status"><span class="badge ${badge.className}">${badge.text}</span></td>
        <td class="source-col-type">${esc(sourceTypeText(item?.type))}</td>
        <td class="source-col-address source-url-cell">
          <div class="mono source-url-main">${esc(url)}</div>
          ${detailText}
        </td>
        <td class="source-col-enabled">
          <label class="source-checkbox-wrap">
            <input type="checkbox" ${item?.enabled ? "checked" : ""} onchange="toggleSourceEnabled('${urlToken}', this.checked)" ${scanRunning ? "disabled" : ""}>
          </label>
        </td>
        <td class="source-col-failed"><span class="source-failure-count">${Number(item?.consecutive_failures || 0)}</span></td>
        <td class="source-col-actions">
          <div class="source-actions">
            ${scanBtn}
            ${deleteBtn}
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

async function loadSources(options = {}) {
  const { silent = false } = options;
  try {
    const res = await fetch("./api/sources");
    const data = await readSourceJsonResponse(res, "加载源列表失败：服务器返回异常");
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "加载源列表失败");
    }
    sourcePool = data;
    renderSources();
    if (!silent && data.scan_running) {
      setSourceBanner("success", "源扫描正在后台执行，页面会自动刷新结果");
    }
  } catch (err) {
    if (!silent) {
      setSourceBanner("error", err?.message || "加载源列表失败");
    }
  }
}

function openSourceModal() {
  $("admin_dropdown").style.display = "none";
  $("source_modal").style.display = "flex";
  setSourceBanner("", "");
  loadSources();
  if (sourcePollInterval) clearInterval(sourcePollInterval);
  sourcePollInterval = setInterval(() => {
    if ($("source_modal").style.display === "flex") {
      loadSources({ silent: true });
    }
  }, 4000);
}

function closeSourceModal() {
  $("source_modal").style.display = "none";
  if (sourcePollInterval) {
    clearInterval(sourcePollInterval);
    sourcePollInterval = null;
  }
}

async function addSource() {
  const input = $("source_add_input");
  const url = input.value.trim();
  if (!url) {
    setSourceBanner("error", "请输入手动源地址");
    return;
  }
  setSourceActionBusy(true);
  try {
    const res = await fetch("./api/source_add", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await readSourceJsonResponse(res, "添加手动源失败：服务器返回异常");
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "添加手动源失败");
    }
    input.value = "";
    setSourceBanner("success", data.message || "手动源已保存");
    await loadSources({ silent: true });
  } catch (err) {
    setSourceBanner("error", err?.message || "添加手动源失败");
  } finally {
    setSourceActionBusy(false);
  }
}

async function triggerSourceScan() {
  setSourceActionBusy(true);
  try {
    const res = await fetch("./api/source_scan", { method: "POST" });
    const data = await readSourceJsonResponse(res, "启动源扫描失败：服务器返回异常");
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "启动源扫描失败");
    }
    setSourceBanner("success", data.message || "已在后台启动源扫描");
    await loadSources({ silent: true });
  } catch (err) {
    setSourceBanner("error", err?.message || "启动源扫描失败");
  } finally {
    if (sourcePool?.scan_running) {
      renderSources();
    } else {
      setSourceActionBusy(false);
    }
  }
}

async function updateSourceFlag(url, payload) {
  try {
    const res = await fetch("./api/source_update", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, ...payload })
    });
    const data = await readSourceJsonResponse(res, "更新源设置失败：服务器返回异常");
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "更新源设置失败");
    }
    setSourceBanner("success", data.message || "源设置已更新");
    await loadSources({ silent: true });
  } catch (err) {
    setSourceBanner("error", err?.message || "更新源设置失败");
    await loadSources({ silent: true });
  }
}

async function toggleSourceEnabled(urlToken, enabled) {
  const url = decodeURIComponent(urlToken);
  await updateSourceFlag(url, { enabled: !!enabled, selected: !!enabled });
}

async function probeSource(urlToken) {
  const url = decodeURIComponent(urlToken);
  if (!url) return;
  sourceProbePending.add(url);
  renderSources();
  try {
    const res = await fetch("./api/source_probe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await readSourceJsonResponse(res, "检测源失败：服务器返回异常");
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "检测源失败");
    }
    setSourceBanner("success", data.message || "源检测已完成");
    await loadSources({ silent: true });
  } catch (err) {
    setSourceBanner("error", err?.message || "检测源失败");
    await loadSources({ silent: true });
  } finally {
    sourceProbePending.delete(url);
    renderSources();
  }
}

async function deleteSource(urlToken) {
  const url = decodeURIComponent(urlToken);
  if (!confirm("确定要删除这个源吗？")) {
    await loadSources({ silent: true });
    return;
  }
  try {
    const res = await fetch("./api/source_delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await readSourceJsonResponse(res, "删除源失败：服务器返回异常");
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "删除源失败");
    }
    setSourceBanner("success", data.message || "源已删除");
    await loadSources({ silent: true });
  } catch (err) {
    setSourceBanner("error", err?.message || "删除源失败");
    await loadSources({ silent: true });
  }
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const port = parseInt($("net_port").value);
  const suffix = $("net_suffix").value.trim();
  const proxyPort = parseInt($("net_proxy_port").value);
  const proxyUser = $("net_proxy_user").value.trim(); // 新增这一行
  const proxyPass = $("net_proxy_pass").value.trim(); // 新增这一行
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (proxyPort === port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }

  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        port: port,
        secret_path: suffix,
        proxy_port: proxyPort,
        proxy_user: proxyUser, // 新增这一行
        proxy_pass: proxyPass, // 新增这一行
        routing_mode: routingMode,
        force_country: forceCountry
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！网页端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";
        
        const inputs = $("network_form").querySelectorAll("input, button, select");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openAdModal() {
  $("ad_modal").style.display = "flex";
}

function closeAdModal() {
  $("ad_modal").style.display = "none";
}

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 前台空闲时自动同步节点与状态，待检测完成后会自动刷新展示
setInterval(async () => {
  if (document.visibilityState !== "visible" || getNodeSyncPaused()) {
    return;
  }
  try {
    await syncNodes();
  } catch (e) {}
}, 3000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("admin_dropdown").style.display = "none";
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetch("./api/gateway_status");
    const data = await res.json();
    if (data.ok && data.services) {
      renderGatewayServices(data.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';
    
    html += `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("admin_dropdown").style.display = "none";
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 2500);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetch("./api/logs");
    const data = await res.json();
    if (data.logs) {
      rawLogsCache = data.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;
  
  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }
  
  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }
  
  const linesHtml = filtered.map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";
    
    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");
  
  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;
  
  term.innerHTML = linesHtml;
  
  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }
  
  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }
  
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    ui_cfg = load_ui_config()
    proxy_user = str(ui_cfg.get("proxy_user") or "").strip()
    proxy_pass = str(ui_cfg.get("proxy_pass") or "").strip()

    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user and proxy_pass:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        for test_url in [
            "https://api.ipify.org",
            "https://ip.sb",
            "http://api.ipify.org",
            "http://ip.sb",
        ]:
            result = _curl_check_ip(test_url)
            if result:
                return result
            
        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            
        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting, proxy_health_failures
    time.sleep(30)
    last_proxy_log_signature: tuple[str, str] | None = None
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                proxy_health_failures = 0
                proxy_ip = str(res.get("ip") or "-")
                proxy_latency_ms = parse_int(res.get("latency_ms"))
                log_signature = ("ok", proxy_ip)
                set_state(
                    proxy_ok=True,
                    proxy_ip=proxy_ip,
                    proxy_latency_ms=proxy_latency_ms,
                    proxy_error=""
                )
                if log_signature != last_proxy_log_signature:
                    log_to_json("INFO", "Proxy", f"代理可用，IP: {proxy_ip}, 延迟: {proxy_latency_ms} ms")
                    last_proxy_log_signature = log_signature
            else:
                error_msg = res.get("error", "未知错误")
                proxy_health_failures += 1
                log_signature = ("error", str(error_msg))
                if active_openvpn_node_id and log_signature != last_proxy_log_signature:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用 (连续失败 {proxy_health_failures}/{PROXY_HEALTH_FAILURE_THRESHOLD}): {error_msg}")
                    last_proxy_log_signature = log_signature
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # If we intended to have an active VPN node but proxy failed, trigger auto-switch
                if active_openvpn_node_id and proxy_health_failures >= PROXY_HEALTH_FAILURE_THRESHOLD:
                    ui_cfg = load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_json(NODES_FILE, [])
                            active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            return True
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        if not secret_path:
            return self.path
        if self.path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if self.path.startswith(prefix):
            return "/" + self.path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_json(NODES_FILE, [])
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries = []
            if log_file.exists():
                try:
                    with lock:
                        with open(log_file, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        entries.append(json.loads(line))
                                    except Exception:
                                        pass
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": entries})
        elif effective_path == "/api/sources":
            self.send_json({"ok": True, **source_pool_public_data()})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/source_scan":
            started = schedule_source_scan(force=True)
            if started:
                self.send_json({"ok": True, "message": "已在后台启动源扫描"})
            else:
                self.send_json({"ok": False, "error": "源扫描正在进行中"}, HTTPStatus.CONFLICT)
            return

        if effective_path == "/api/source_add":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                save_pool = add_manual_source(str(payload.get("url") or ""))
                self.send_json({"ok": True, "message": "手动源已保存", "sources": save_pool.get("sources", [])})
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/source_probe":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                probe_data = probe_single_source(str(payload.get("url") or ""))
                entry = probe_data.get("entry", {})
                status_text = "可用" if entry.get("healthy") else "不可用"
                self.send_json({"ok": True, "message": f"单个源检测完成：{status_text}", "entry": entry})
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except RuntimeError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.CONFLICT)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/source_delete":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                save_pool = delete_source(str(payload.get("url") or ""))
                self.send_json({"ok": True, "message": "源已删除", "sources": save_pool.get("sources", [])})
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/source_update":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                enabled = payload["enabled"] if "enabled" in payload else None
                selected = payload["selected"] if "selected" in payload else None
                save_pool = update_source_flags(
                    str(payload.get("url") or ""),
                    enabled=enabled,
                    selected=selected,
                )
                self.send_json({"ok": True, "message": "源设置已更新", "sources": save_pool.get("sources", [])})
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/source_preferences":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                save_pool = update_source_preferences(bool(payload.get("use_selected_only")))
                self.send_json({"ok": True, "message": "源偏好已更新", "use_selected_only": save_pool.get("use_selected_only", False)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/update_credentials":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                
                if not new_username or not new_password:
                    self.send_json({"ok": False, "error": "用户名和密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                ui_cfg["username"] = new_username
                ui_cfg["password"] = new_password
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                new_proxy_port = payload.get("proxy_port")
                # 新增以下两行，接收前端网页传来的账号和密码
                new_proxy_user = str(payload.get("proxy_user") or "").strip() 
                new_proxy_pass = str(payload.get("proxy_pass") or "").strip()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if new_proxy_port_int == new_port_int:
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                ui_cfg["proxy_port"] = new_proxy_port_int
                # 新增以下两行，写入配置文件
                ui_cfg["proxy_user"] = new_proxy_user 
                ui_cfg["proxy_pass"] = new_proxy_pass
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix or new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，系统及网页端口或后缀变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "message": "配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                routing_protocol = normalize_routing_protocols(payload.get("routing_protocol", ["udp"]))
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                if not routing_protocol:
                    self.send_json({"ok": False, "error": "请至少保留一种协议"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["routing_protocol"] = routing_protocol
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": run_node_refresh(force=True, disconnect_active=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                threading.Thread(target=run_node_refresh, kwargs={"force": False, "disconnect_active": False}, daemon=True).start()
                self.send_json({"ok": True, "message": "已在后台启动节点更新流程"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                stop_active_openvpn()
                with lock:
                    nodes = read_json(NODES_FILE, [])
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                if length > 0:
                    self.rfile.read(length)
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = int(ui_cfg.get("port", UI_PORT))
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()

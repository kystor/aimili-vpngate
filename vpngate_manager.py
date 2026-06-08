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
                print(f"[璀﹀憡] 缁戝畾 Web 绠＄悊鍚庡彴 IPv6 {host}:{port} 澶辫触 ({e})锛屾鍦ㄥ皾璇曞洖閫€鑷?IPv4 {fallback_host} ...", flush=True)
                # 鍏抽棴绗竴娆″け璐ユ椂鍙兘宸插垱寤虹殑 socket
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
SOURCE_SCAN_HOUR = int(os.environ.get("SOURCE_SCAN_HOUR", "0"))
SOURCE_SCAN_MAX_CANDIDATES = int(os.environ.get("SOURCE_SCAN_MAX_CANDIDATES", "10"))
MAX_HEALTHY_FETCH_SOURCES = int(os.environ.get("MAX_HEALTHY_FETCH_SOURCES", "5"))
SOURCE_DELETE_FAIL_COUNT = int(os.environ.get("SOURCE_DELETE_FAIL_COUNT", "3"))
# 銆愪紭鍖栥€戝皢榛樿鍗曟浠?API 鎵弿鐨勬渶澶ц妭鐐规暟閲忎粠 300 鎻愬崌鍒?2000
# 杩欐牱鍙互涓€娆℃€ф妸瀹樻柟 API 鎺ュ彛杩斿洖鐨勬墍鏈夊彲鐢ㄨ妭鐐瑰叏閮ㄥ悆杩涘唴瀛?MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "2000"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
# 灏嗗師鏈殑 "127.0.0.1" 淇敼涓?"0.0.0.0"锛屼互鍏佽鍏綉鐨?hy2 鑺傜偣杩炴帴鏈満鐨勪唬鐞嗙鍙?LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "0.0.0.0")
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
MANUAL_TEST_TIMEOUT_SECONDS = int(os.environ.get("MANUAL_TEST_TIMEOUT_SECONDS", "8"))
KEEP_OLD_NODE_LATENCY_MS = int(os.environ.get("KEEP_OLD_NODE_LATENCY_MS", "50"))
MAX_CACHED_NODES = int(os.environ.get("MAX_CACHED_NODES", "1200"))

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
SOURCES_FILE = DATA_DIR / "sources.json"

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
heavy_task_queue: queue.Queue[dict[str, Any]] = queue.Queue()
heavy_task_meta_lock = threading.Lock()
queued_heavy_task_keys: set[str] = set()
running_heavy_task_key = ""
heavy_task_runtime_lock = threading.RLock()

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

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
            "fixed_node_id": "",
            "source_only_selected": False,
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["proxy_port", "proxy_user", "proxy_pass", "routing_mode", "force_country", "routing_ip_type", "routing_protocol", "connection_enabled", "fixed_node_id", "source_only_selected"]:
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

# 鍒濆鍖栨椂浼樺厛浠?ui_auth.json 鍔犺浇淇濆瓨鐨勪唬鐞嗗嚭绔欑鍙ｅ拰缃戦〉绔彛閰嶇疆浠ヨ鐩栫幆澧冨彉閲?try:
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
                        print(f"[娓呯悊] 宸插垹闄?澶╁墠鐨勬棫鏃ュ織鏂囦欢: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[娓呯悊閿欒] 娓呯悊鏃ф棩蹇楀け璐? {e}", flush=True)

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
    state.setdefault("last_source_scan_at", 0.0)
    state.setdefault("last_source_scan_message", "")
    state.setdefault("last_source_scan_day", "")
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
    state["source_only_selected"] = bool(ui_cfg.get("source_only_selected", False))
    sources = load_sources()
    state["source_total"] = len(sources)
    state["source_healthy"] = len([item for item in sources if item.get("healthy") and item.get("enabled")])
    running_task, queued_count = heavy_task_status()
    state["heavy_task_running"] = running_task
    state["heavy_task_queued"] = queued_count
    return state

def build_source_record(
    url: str,
    source_type: str,
    *,
    enabled: bool = True,
    selected: bool = False,
) -> dict[str, Any]:
    now = time.time()
    return {
        "id": safe_name(url),
        "url": str(url).strip(),
        "source_type": source_type,
        "enabled": enabled,
        "selected": selected,
        "healthy": False,
        "fail_count": 0,
        "last_ok_at": 0.0,
        "last_checked_at": 0.0,
        "last_error": "",
        "last_status_code": 0,
        "created_at": now,
        "updated_at": now,
    }

def normalize_source_record(item: dict[str, Any]) -> dict[str, Any]:
    url = str(item.get("url") or "").strip()
    source_type = str(item.get("source_type") or "auto").strip() or "auto"
    base = build_source_record(
        url,
        source_type,
        enabled=bool(item.get("enabled", True)),
        selected=bool(item.get("selected", False)),
    )
    base.update({
        "id": str(item.get("id") or safe_name(url)),
        "healthy": bool(item.get("healthy", False)),
        "fail_count": max(0, parse_int(item.get("fail_count"))),
        "last_ok_at": float(item.get("last_ok_at", 0) or 0),
        "last_checked_at": float(item.get("last_checked_at", 0) or 0),
        "last_error": str(item.get("last_error") or ""),
        "last_status_code": parse_int(item.get("last_status_code")),
        "created_at": float(item.get("created_at", base["created_at"]) or base["created_at"]),
        "updated_at": float(item.get("updated_at", base["updated_at"]) or base["updated_at"]),
    })
    return base

def default_source_urls() -> list[tuple[str, str]]:
    urls: list[tuple[str, str]] = [(API_URL, "official")]
    extra_values = str(EXTRA_VPNGATE_API_URLS or "").replace("\n", ",").split(",")
    for item in extra_values:
        url = str(item).strip()
        if url and not any(existing == url for existing, _ in urls):
            urls.append((url, "manual"))
    return urls

def load_sources() -> list[dict[str, Any]]:
    items = read_json(SOURCES_FILE, [])
    sources: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    if isinstance(items, list):
        for raw in items:
            if not isinstance(raw, dict):
                continue
            source = normalize_source_record(raw)
            if not source["url"] or source["url"] in seen_urls:
                continue
            seen_urls.add(source["url"])
            sources.append(source)
    for url, source_type in default_source_urls():
        if url in seen_urls:
            continue
        seen_urls.add(url)
        sources.append(build_source_record(url, source_type, enabled=True, selected=(source_type == "official")))
    return sources

def save_sources(sources: list[dict[str, Any]]) -> None:
    cleaned: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for item in sources:
        if not isinstance(item, dict):
            continue
        source = normalize_source_record(item)
        if not source["url"] or source["url"] in seen_urls:
            continue
        seen_urls.add(source["url"])
        cleaned.append(source)
    write_json(SOURCES_FILE, cleaned)

def update_source_state(url: str, ok: bool, *, error: str = "", status_code: int = 0) -> None:
    now = time.time()
    with lock:
        sources = load_sources()
        changed = False
        kept: list[dict[str, Any]] = []
        for item in sources:
            if item["url"] != url:
                kept.append(item)
                continue
            changed = True
            item["last_checked_at"] = now
            item["last_status_code"] = status_code
            item["updated_at"] = now
            if ok:
                item["healthy"] = True
                item["fail_count"] = 0
                item["last_ok_at"] = now
                item["last_error"] = ""
                kept.append(item)
                continue
            item["healthy"] = False
            item["fail_count"] = parse_int(item.get("fail_count")) + 1
            item["last_error"] = error
            if item.get("source_type") == "manual":
                kept.append(item)
                continue
            if item["fail_count"] < SOURCE_DELETE_FAIL_COUNT:
                kept.append(item)
                continue
            log_to_json("WARNING", "Source", f"自动源连续失败已删除: {url} | {error}")
        if changed:
            save_sources(kept)

def heavy_task_status() -> tuple[str, int]:
    with heavy_task_meta_lock:
        return running_heavy_task_key, len(queued_heavy_task_keys)

def enqueue_heavy_task(task_type: str, runner: Any, *, dedupe_key: str = "", description: str = "") -> bool:
    key = dedupe_key or task_type
    with heavy_task_meta_lock:
        if running_heavy_task_key == key or key in queued_heavy_task_keys:
            return False
        queued_heavy_task_keys.add(key)
    heavy_task_queue.put({
        "task_type": task_type,
        "dedupe_key": key,
        "runner": runner,
        "description": description or task_type,
    })
    return True

def run_heavy_task_queue() -> None:
    global running_heavy_task_key
    while True:
        task = heavy_task_queue.get()
        key = str(task.get("dedupe_key") or "")
        description = str(task.get("description") or task.get("task_type") or "task")
        with heavy_task_meta_lock:
            queued_heavy_task_keys.discard(key)
            running_heavy_task_key = key
        try:
            log_to_json("INFO", "Main", f"重任务开始排队执行: {description}")
            runner = task.get("runner")
            if callable(runner):
                runner()
        except Exception as exc:
            print(f"[重任务] 执行失败: {description} -> {exc}", flush=True)
            log_to_json("ERROR", "Main", f"重任务执行失败: {description} -> {exc}")
        finally:
            with heavy_task_meta_lock:
                if running_heavy_task_key == key:
                    running_heavy_task_key = ""
            heavy_task_queue.task_done()

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

def fetch_text_from_many(urls: list[str]) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for url in urls:
        try:
            text = fetch_api_text(url, use_ssl_verify=url.startswith("https://"))
            if text.strip():
                results.append((url, text))
        except Exception as exc:
            print(f"[鎶撳彇鑺傜偣] 鏉ユ簮澶辫触: {url} -> {exc}", flush=True)
            log_to_json("WARNING", "Main", f"鑺傜偣鏉ユ簮澶辫触: {url} -> {exc}")
    return results

def parse_configured_source_urls(raw: Any) -> list[str]:
    if isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        items = re.split(r"[\s,]+", str(raw or ""))
    urls: list[str] = []
    for item in items:
        url = str(item or "").strip()
        if url and url not in urls:
            urls.append(url)
    return urls

def normalize_source_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    path = parsed.path.rstrip("/")
    if path.endswith("/api/iphone"):
        path = path + "/"
    elif path.endswith("/api/iphone/"):
        pass
    else:
        path = (path + "/api/iphone/") if path else "/api/iphone/"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

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
            return [str(item).strip() for item in cached_urls if str(item).strip()]
    except Exception:
        pass
    source_pages = [MIRROR_SITES_URL, *parse_configured_source_urls(MIRROR_SITES_URLS)]
    urls: list[str] = []
    for source_url in source_pages:
        if not source_url:
            continue
        try:
            text = fetch_api_text(source_url)
        except Exception as exc:
            print(f"[源扫描] 获取镜像页失败: {source_url} -> {exc}", flush=True)
            log_to_json("WARNING", "Source", f"获取镜像页失败: {source_url} -> {exc}")
            continue
        for match in re.findall(r"https?://[A-Za-z0-9._:/?=&%-]+", text):
            clean = match.rstrip("/ \t\r\n")
            if clean and clean not in urls:
                urls.append(clean)
    urls = urls[:SOURCE_SCAN_MAX_CANDIDATES]
    try:
        write_json(cache_file, {"cached_at": now, "urls": urls})
    except Exception:
        pass
    return urls

def discover_auto_source_urls() -> list[str]:
    urls: list[str] = []
    for item in load_mirror_site_urls():
        api_url = normalize_source_url(item)
        if api_url and api_url not in urls:
            urls.append(api_url)
    return urls

def source_priority(item: dict[str, Any]) -> tuple[int, int, float]:
    source_type = str(item.get("source_type") or "auto")
    type_rank = {"manual": 0, "official": 1, "auto": 2}.get(source_type, 9)
    selected_rank = 0 if item.get("selected") else 1
    return (selected_rank, type_rank, -float(item.get("last_ok_at", 0) or 0))

def pick_fetch_sources() -> list[dict[str, Any]]:
    sources = load_sources()
    ui_cfg = load_ui_config()
    only_selected = bool(ui_cfg.get("source_only_selected", False))
    enabled = [item for item in sources if item.get("enabled")]
    if only_selected:
        enabled = [item for item in enabled if item.get("selected")]
    healthy = [item for item in enabled if item.get("healthy")]
    picked = healthy or enabled
    picked = sorted(picked, key=source_priority)
    return picked[:MAX_HEALTHY_FETCH_SOURCES]

def collect_candidate_source_urls() -> list[str]:
    return [item["url"] for item in pick_fetch_sources() if str(item.get("url") or "").strip()]

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
            print(f"[fetch_api_text] 鐩戞祴鍒颁笂娓镐唬鐞?({ptype}://{phost}:{pport})锛屽皾璇曢€氳繃浠ｇ悊鑾峰彇 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 閫氳繃浠ｇ悊鑾峰彇 API 澶辫触: {e}锛屽皾璇曚娇鐢ㄧ洿杩?榛樿绯荤粺浠ｇ悊...", flush=True)
            log_to_json("WARNING", "Main", f"浣跨敤浠ｇ悊 {ptype}://{phost}:{pport} 鑾峰彇 API 澶辫触: {e}")

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
        raise RuntimeError("鑺傜偣缂哄皯閰嶇疆鏂囦欢璺緞")
    config_path = Path(config_file)
    if config_path.exists():
        return config_path
    config_text = str(node.get("config_text") or "")
    if not config_text:
        raise RuntimeError(f"鑺傜偣閰嶇疆鏂囦欢涓嶅瓨鍦? {config_path}")
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
                last_error = RuntimeError("源返回空数据")
            except Exception as exc:
                last_error = exc
                print(f"[源抓取] 失败: {url} -> {exc}", flush=True)
                log_to_json("WARNING", "Source", f"源抓取失败: {url} -> {exc}")
    if last_error is not None:
        raise last_error
    raise RuntimeError("源未返回任何节点数据")

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_endpoints: set[tuple[str, int, str]] = set()
    source_summaries: list[str] = []
    has_cache = len(cached_nodes()) > 0
    source_urls = collect_candidate_source_urls()
    if not source_urls:
        raise RuntimeError("当前没有可用的 API 源，请先到源管理中启用或勾选可用源")
    log_to_json("INFO", "Main", f"开始抓取节点，使用 {len(source_urls)} 个源")
    for index, source_url in enumerate(source_urls, start=1):
        try:
            rows, _ = fetch_rows_from_source(source_url, 1 if has_cache or index > 1 else 2)
            update_source_state(source_url, True)
        except Exception as exc:
            update_source_state(source_url, False, error=str(exc))
            source_summaries.append(f"源{index}失败")
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
        source_summaries.append(f"源{index}+{added}")
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
        "resolving": ("瑙ｆ瀽鍩熷悕", "姝ｅ湪瑙ｆ瀽鏈嶅姟鍣ㄥ煙鍚嶄笌 IP 鍦板潃..."),
        "udp link local": ("鐗╃悊杩炴帴", "宸插垱寤烘湰鍦板鎺ュ瓧锛屽紑濮嬪皾璇曞彂閫佹暟鎹寘..."),
        "tcp link local": ("鐗╃悊杩炴帴", "宸插垱寤烘湰鍦板鎺ュ瓧锛屽紑濮嬪皾璇曞彂閫佹暟鎹寘..."),
        "tls: initial packet": ("璇佷功鎻℃墜", "宸叉垚鍔熷彂閫侀鍖咃紝姝ｅ湪涓庤繙绋嬫湇鍔″櫒寤虹珛 TLS 瀹夊叏閫氶亾..."),
        "verify ok": ("璇佷功鏍￠獙", "鏈嶅姟鍣ㄨ瘉涔︽牎楠屾垚鍔燂紝姝ｅ湪杩涜韬唤楠岃瘉..."),
        "peer connection initiated": ("鍗忓晢鍔犲瘑", "鎺у埗閫氶亾宸插缓绔嬶紝宸插垵濮嬪寲涓庢湇鍔″櫒鐨勫姞瀵嗗绛夎繛鎺?.."),
        "push_request": ("璇锋眰閰嶇疆", "姝ｅ湪鍚戞湇鍔″櫒鍙戦€?PUSH_REQUEST 璇锋眰閰嶇疆鍙傛暟涓?IP 鍒嗛厤..."),
        "push_reply": ("搴旂敤閰嶇疆", "宸叉帴鏀舵湇鍔″櫒 PUSH_REPLY锛岃幏鍙栧埌 IP 鍒嗛厤锛屾鍦ㄥ噯澶囬厤缃綉鍗?.."),
        "tun/tap device": ("鍒涘缓缃戝崱", "姝ｅ湪鍒涘缓铏氭嫙閫氶亾骞舵墦寮€ TUN 铏氭嫙缃戝崱璁惧..."),
        "do_ifconfig": ("缃戝崱閰嶇疆", "姝ｅ湪涓鸿櫄鎷熺綉鍗￠厤缃?IP 鍦板潃鍙婄浉鍏崇綉缁滃睘鎬?.."),
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
        return False, "[閿欒浠ｇ爜 2001] [ERR_OVPN_CMD_NOT_FOUND] 鏈壘鍒?openvpn 鍛戒护銆傚師鍥? 绯荤粺鏈畨瑁?openvpn锛屾垨 PATH 鐜鍙橀噺涓嶆纭€?, None
    except OSError as exc:
        return False, f"[閿欒浠ｇ爜 2002] [ERR_OVPN_START_FAILED] openvpn 鍚姩澶辫触: {exc}銆傚師鍥? 绯荤粺鏉冮檺涓嶈冻鎴栭厤缃啿绐併€?, None

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
        message = f"[閿欒浠ｇ爜 {err_code}] {diag_msg} (鍘熷鏃ュ織灏鹃儴: {tail[-1][-100:] if tail else '鏃?})"
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
            # 閰嶇疆鍙嶅悜璺緞杩囨护 rp_filter 涓?loose 妯″紡 (2)锛岄槻姝㈠洖鍖呰鍐呮牳闈欓粯涓㈠純
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
        print("[璺敱閰嶇疆澶辫触] [閿欒浠ｇ爜 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 绛栫暐璺敱閰嶇疆澶辫触銆傚師鍥? 鏃犳硶鍚戣矾鐢辫〃 100 娣诲姞榛樿璺敱锛岃繖鍙兘浼氬鑷撮€氳繃 VPN 鎺ュ彛鐨勫嚭绔欒矾鐢辨棤娉曟甯歌В鏋愩€傝妫€鏌ョ郴缁熸槸鍚︽敮鎸佺瓥鐣ヨ矾鐢便€乮proute2 宸ュ叿鏄惁瀹屾暣锛屼互鍙婃槸鍚﹀叿鏈?root 鏉冮檺銆?, flush=True)
        log_to_json("ERROR", "Routing", "[閿欒浠ｇ爜 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 绛栫暐璺敱閰嶇疆澶辫触銆傚師鍥? 鏃犳硶鍚戣矾鐢辫〃 100 娣诲姞榛樿璺敱")

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

def should_run_daily_source_scan(state: dict[str, Any], now: float) -> bool:
    local_now = time.localtime(now)
    today = time.strftime("%Y-%m-%d", local_now)
    if str(state.get("last_source_scan_day") or "") == today:
        return False
    return local_now.tm_hour >= SOURCE_SCAN_HOUR

def source_scan_priority(item: dict[str, Any]) -> tuple[int, int, float]:
    source_type = str(item.get("source_type") or "auto")
    type_rank = {"manual": 0, "official": 1, "auto": 2}.get(source_type, 9)
    healthy_rank = 0 if not item.get("healthy") else 1
    checked_at = float(item.get("last_checked_at", 0) or 0)
    return (type_rank, healthy_rank, checked_at)

def run_source_scan() -> str:
    with heavy_task_runtime_lock:
        sources = load_sources()
        source_by_url = {item["url"]: item for item in sources}
        for url, source_type in default_source_urls():
            if url not in source_by_url:
                source_by_url[url] = build_source_record(url, source_type, enabled=True, selected=(source_type == "official"))
        for url in discover_auto_source_urls():
            if url not in source_by_url:
                source_by_url[url] = build_source_record(url, "auto")
        sources = list(source_by_url.values())
        save_sources(sources)
        targets = [item for item in sources if item.get("enabled")]
        targets = sorted(targets, key=source_scan_priority)[:SOURCE_SCAN_MAX_CANDIDATES]
        summaries: list[str] = []
        for item in targets:
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            try:
                rows, _ = fetch_rows_from_source(url, 1)
                update_source_state(url, True)
                summaries.append(f"{url} 成功 {min(len(rows), MAX_SCAN_ROWS)}")
            except Exception as exc:
                update_source_state(url, False, error=str(exc))
                summaries.append(f"{url} 失败")
        now = time.time()
        healthy_count = len([item for item in load_sources() if item.get("enabled") and item.get("healthy")])
        message = f"源扫描完成，本轮检测 {len(targets)} 个，健康源 {healthy_count} 个"
        set_state(
            last_source_scan_at=now,
            last_source_scan_day=time.strftime("%Y-%m-%d", time.localtime(now)),
            last_source_scan_message=message,
        )
        log_to_json("INFO", "Source", message if not summaries else f"{message}，{' / '.join(summaries[:6])}")
        return message

def request_source_scan() -> bool:
    return enqueue_heavy_task(
        "source_scan",
        run_source_scan,
        dedupe_key="source_scan",
        description="每日源扫描",
    )

def request_node_refresh(force: bool = False, disconnect_active: bool = False) -> bool:
    def runner() -> None:
        with heavy_task_runtime_lock:
            run_node_refresh(force=force, disconnect_active=disconnect_active)
    return enqueue_heavy_task(
        "node_refresh",
        runner,
        dedupe_key="node_refresh",
        description="节点更新",
    )

def list_sources_payload() -> dict[str, Any]:
    sources = sorted(load_sources(), key=source_priority)
    return {
        "sources": sources,
        "source_only_selected": bool(load_ui_config().get("source_only_selected", False)),
        "healthy_count": len([item for item in sources if item.get("enabled") and item.get("healthy")]),
        "total_count": len(sources),
    }

def save_ui_config(ui_cfg: dict[str, Any]) -> None:
    auth_file = DATA_DIR / "ui_auth.json"
    with lock:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")

def upsert_source(url: str, *, source_type: str = "manual", enabled: bool = True, selected: bool = False) -> dict[str, Any]:
    api_url = normalize_source_url(url)
    if not api_url:
        raise ValueError("源地址格式不正确")
    with lock:
        sources = load_sources()
        for item in sources:
            if item["url"] == api_url:
                item["enabled"] = enabled
                item["selected"] = selected
                item["source_type"] = source_type or item.get("source_type") or "manual"
                item["updated_at"] = time.time()
                save_sources(sources)
                return item
        record = build_source_record(api_url, source_type or "manual", enabled=enabled, selected=selected)
        sources.append(record)
        save_sources(sources)
        return record

def update_source_flags(source_id: str, *, enabled: Any = None, selected: Any = None) -> bool:
    with lock:
        sources = load_sources()
        changed = False
        for item in sources:
            if str(item.get("id") or "") != source_id:
                continue
            if enabled is not None:
                item["enabled"] = bool(enabled)
            if selected is not None:
                item["selected"] = bool(selected)
            item["updated_at"] = time.time()
            changed = True
            break
        if changed:
            save_sources(sources)
        return changed

def delete_source(source_id: str) -> bool:
    with lock:
        sources = load_sources()
        kept = [item for item in sources if str(item.get("id") or "") != source_id]
        if len(kept) == len(sources):
            return False
        save_sources(kept)
        return True

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
    with heavy_task_runtime_lock:
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
    with heavy_task_runtime_lock:
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
    batch_size = limit if limit is not None else MAX_MAINTAIN_TEST_NODES
    if batch_size <= 0:
        return
    def runner() -> None:
        if not followup_test_lock.acquire(blocking=False):
            return
        try:
            with heavy_task_runtime_lock:
                with lock:
                    nodes = read_json(NODES_FILE, [])
                    node_ids = [
                        str(node.get("id") or "")
                        for node in nodes
                        if not node.get("active") and node.get("probe_status") == "not_checked"
                    ][:batch_size]
                if not node_ids:
                    return
                log_to_json("INFO", "Main", f"后台补测启动，本轮准备检测 {len(node_ids)} 个待检测节点")
                set_node_testing_state(node_ids, True)
                try:
                    test_multiple_nodes(node_ids)
                finally:
                    set_node_testing_state(node_ids, False)
        except Exception as exc:
            print(f"[后台补测] 检测待检测节点失败: {exc}", flush=True)
            log_to_json("WARNING", "Main", f"后台补测失败: {exc}")
        finally:
            followup_test_lock.release()

    enqueue_heavy_task("followup_test", runner, dedupe_key="followup_test", description="后台补测待检测节点")

def auto_switch_node(attempt: int = 0) -> None:
    global is_connecting
    if attempt >= 3:
        print("[鑷姩鍒囨崲] 杩炵画鍒囨崲澶辫触 3 娆★紝鍋滄鏈疆鑷姩鍒囨崲", flush=True)
        return

    ui_cfg = load_ui_config()
    if not ui_cfg.get("connection_enabled", True):
        print("[鑷姩鍒囨崲] 褰撳墠宸插叧闂嚜鍔ㄨ繛鎺ワ紝涓嶆墽琛屽垏鎹?, flush=True)
        return
    if ui_cfg.get("routing_mode") == "fixed_ip":
        print("[鑷姩鍒囨崲] 褰撳墠鏄浐瀹氳妭鐐规ā寮忥紝涓嶆墽琛岃嚜鍔ㄥ垏鎹?, flush=True)
        return

    with lock:
        nodes = read_json(NODES_FILE, [])
    candidates = [node for node in nodes if node.get("probe_status") == "available" and not node.get("active")]
    candidates = filter_nodes_for_routing(candidates, ui_cfg)
    candidates = sort_all_nodes(candidates)

    if not candidates:
        msg = "褰撳墠娌℃湁鍙垏鎹㈢殑鍙敤鑺傜偣"
        print(f"[鑷姩鍒囨崲] {msg}", flush=True)
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
    msg = f"鍑嗗鑷姩鍒囨崲鍒拌妭鐐?{next_node['id']}"
    print(f"[鑷姩鍒囨崲] {msg}", flush=True)
    log_to_json("INFO", "VPN", msg)
    with lock:
        is_connecting = False
    try:
        connect_node(str(next_node["id"]))
    except Exception as exc:
        print(f"[鑷姩鍒囨崲] 鑺傜偣 {next_node['id']} 杩炴帴澶辫触: {exc}", flush=True)
        log_to_json("WARNING", "VPN", f"鑷姩鍒囨崲澶辫触: {exc}")
        auto_switch_node(attempt + 1)

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting, proxy_health_failures
    with lock:
        if is_connecting:
            return "宸叉湁杩炴帴浠诲姟姝ｅ湪鎵ц"
        is_connecting = True
        active_openvpn_node_id = node_id
    set_state(
        active_openvpn_node_id=node_id,
        is_connecting=True,
        active_node_latency="姝ｅ湪杩炴帴",
        last_check_message="姝ｅ湪鍒濆鍖栬繛鎺?,
    )

    try:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"鏈壘鍒拌妭鐐? {node_id}")

        ui_cfg = load_ui_config()
        allowed_protocols = set(normalize_routing_protocols(ui_cfg.get("routing_protocol", ["udp"])))
        if node_protocol(node) not in allowed_protocols:
            raise RuntimeError("褰撳墠鍗忚绛涢€変笉鍏佽杩炴帴杩欎釜鑺傜偣")

        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")

        set_state(active_node_latency="娓呯悊鏃ц繛鎺?, last_check_message="姝ｅ湪鍏抽棴鏃ц繛鎺?)
        stop_active_openvpn()

        set_state(active_node_latency="鍑嗗閰嶇疆", last_check_message="姝ｅ湪鍑嗗 OpenVPN 閰嶇疆")
        config_path = ensure_node_config_path(node)

        set_state(active_node_latency="寤虹珛闅ч亾", last_check_message="姝ｅ湪鍚姩 OpenVPN 鏍稿績")
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
                active_node_latency="杩炴帴澶辫触",
                last_check_message=f"鑺傜偣杩炴帴澶辫触: {message}",
            )
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)

        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id

        set_state(active_node_latency="閰嶇疆璺敱", last_check_message="姝ｅ湪璁剧疆绛栫暐璺敱")
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
                item["probe_message"] = f"褰撳墠姝ｅ湪浣跨敤锛屼唬鐞嗗叆鍙? {get_proxy_display_url()}"
                item["latency_ms"] = last_active_latency or item.get("latency_ms", 0)
                item["probed_at"] = time.time()
        write_json(NODES_FILE, nodes)

        set_state(last_check_message="姝ｅ湪妫€娴嬫湰鍦颁唬鐞嗗嚭鍙?)
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
                proxy_error=proxy_result.get("error", "鏈煡閿欒"),
            )

        latency_text = f"{last_active_latency} ms" if last_active_latency > 0 else "鏈祴鍑哄欢杩?
        set_state(
            active_openvpn_node_id=node_id,
            is_connecting=False,
            active_node_latency=latency_text,
            last_check_message=f"鑺傜偣 {node_id} 宸茶繛鎺?,
        )
        log_to_json("INFO", "VPN", f"鑺傜偣 {node_id} 杩炴帴鎴愬姛")
        schedule_followup_tests(MAX_MAINTAIN_TEST_NODES)
        return f"Connected {node_id}"
    finally:
        with lock:
            is_connecting = False

def maintain_valid_nodes(force: bool = False) -> str:
    global is_connecting
    ensure_dirs()
    if not maintain_job_lock.acquire(blocking=False):
        return "鑺傜偣缁存姢宸插湪杩涜涓?

    with lock:
        is_connecting = True

    try:
        if force:
            stop_active_openvpn()

        set_state(is_connecting=True, last_check_message="姝ｅ湪鎶撳彇鏈€鏂拌妭鐐瑰垪琛?)
        try:
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=str(exc))
            return f"鎶撳彇鑺傜偣澶辫触: {exc}"

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
            set_state(is_connecting=True, last_check_message=f"姝ｅ湪妫€娴?{len(to_test)} 涓妭鐐?)
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

        message = f"宸叉姄鍙?{len(candidates)} 涓妭鐐癸紝褰撳墠鍙敤 {valid_nodes_count} 涓?
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            valid_nodes=valid_nodes_count,
            active_openvpn_node_id=active_openvpn_node_id,
            is_connecting=False,
        )
        schedule_followup_tests(MAX_MAINTAIN_TEST_NODES)
        return message
    finally:
        with lock:
            is_connecting = False
        maintain_job_lock.release()

def run_node_refresh(force: bool = False, disconnect_active: bool = False) -> str:
    global is_connecting
    ensure_dirs()
    if not maintain_job_lock.acquire(blocking=False):
        return "鑺傜偣缁存姢宸插湪杩涜涓?

    with lock:
        is_connecting = True

    try:
        if force and disconnect_active:
            stop_active_openvpn()

        set_state(is_connecting=True, last_check_message="姝ｅ湪鎶撳彇鏈€鏂拌妭鐐瑰垪琛?)
        try:
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            set_state(
                last_fetch_at=time.time(),
                last_fetch_status="error",
                last_fetch_message=str(exc),
                is_connecting=False,
            )
            return f"鎶撳彇鑺傜偣澶辫触: {exc}"

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
            set_state(is_connecting=True, last_check_message=f"姝ｅ湪妫€娴?{len(batch_ids)} 涓妭鐐?)
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

        message = f"宸叉姄鍙?{len(candidates)} 涓妭鐐癸紝褰撳墠鍙敤 {valid_nodes_count} 涓紝褰撳墠鍗忚鍙敤 {routed_valid_nodes} 涓?
        if cooldown_until > 0:
            message += "锛屽簱瀛樹笉瓒筹紝杩涘叆 1 灏忔椂鍐峰嵈"

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
        schedule_followup_tests(MAX_MAINTAIN_TEST_NODES)
        return message
    finally:
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
            now = time.time()
            should_refresh, refresh_reason = should_trigger_auto_refresh(current_state, routed_valid_nodes, now)
            set_state(
                valid_nodes=total_valid_nodes,
                routed_valid_nodes=routed_valid_nodes,
                last_auto_refresh_reason=refresh_reason if should_refresh else current_state.get("last_auto_refresh_reason", ""),
            )
            if should_run_daily_source_scan(current_state, now):
                request_source_scan()
            schedule_followup_tests(MAX_MAINTAIN_TEST_NODES)
            if should_refresh:
                request_node_refresh(force=False, disconnect_active=False)
        except Exception as exc:
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")

        time.sleep(COLLECTOR_DECISION_INTERVAL_SECONDS)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 瀹夊叏鐧诲綍</title>
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
      <p class="login-subtitle">璇疯緭鍏ユ偍鐨勭鐞嗚处鍙峰拰瀹夊叏瀵嗙爜浠ョ户缁?/p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">绠＄悊璐﹀彿</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="璇疯緭鍏ョ鐞嗚处鍙? required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">瀹夊叏瀵嗙爜</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="璇疯緭鍏ュ畨鍏ㄥ瘑鐮? required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>鐧诲綍</span>
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
      submitBtn.querySelector("span").textContent = "姝ｅ湪楠岃瘉...";
      
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
          errorText.textContent = data.error || "璐﹀彿鎴栧瘑鐮佷笉姝ｇ‘锛岃閲嶆柊杈撳叆";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "鐧诲綍";
        }
      } catch (err) {
        errorText.textContent = "杩炴帴鏈嶅姟鍣ㄥけ璐ワ紝璇风◢鍚庨噸璇?;
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "鐧诲綍";
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
  <title>AimiliVPN 鑺傜偣姹犵鐞嗙郴缁?/title>
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
      AimiliVPN 鑺傜偣绠＄悊绯荤粺
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>鏈嶅姟鍔犺浇涓?..</div>
  </div>
  <div class="btn-group">
    <div class="routing-select-wrapper">
      <label for="header_routing_country" style="color: var(--text-secondary); font-weight: 500; white-space: nowrap;">鍑虹珯鍥藉:</label>
      <select id="header_routing_country">
        <option value="">鍏ㄩ儴</option>
      </select>
    </div>
    <div class="routing-select-wrapper">
      <label for="header_routing_ip_type" style="color: var(--text-secondary); font-weight: 500; white-space: nowrap;">IP绫诲瀷:</label>
      <select id="header_routing_ip_type">
        <option value="all">鍏ㄩ儴IP</option>
        <option value="residential">浠呴潤鎬佷綇瀹匢P</option>
        <option value="hosting">浠呮満鎴縄P</option>
      </select>
    </div>
    <div class="routing-select-wrapper">
      <span style="color: var(--text-secondary); font-weight: 500; white-space: nowrap;">鍗忚:</span>
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
        <a href="https://github.com/baoweise-bot/aimili-vpngate" target="_blank">姝ｅ紡鐗?/a>
        <a href="https://github.com/baoweise-bot/aimili-vpngate/tree/bate" target="_blank">娴嬭瘯鐗?/a>
      </div>
    </div>
    <a href="https://t.me/arestemple" target="_blank" class="btn-telegram">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336-.063.065-.129.13-.19.193-.34.347-.597.609-.043.974.265.175.474.319.684.457.228.15.457.301.765.503.074.049.143.098.207.143.297.206.58.404.916.373.195-.018.398-.2.502-.754.25-1.332.74-4.22.842-5.281.01-.088.001-.22-.103-.312-.104-.092-.252-.09-.323-.087a1.52 1.52 0 0 0-.254.04z"/></svg>
      Telegram
    </a>
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      鏇存柊鑺傜偣
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        绠＄悊鍛?        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          璐﹀彿瀵嗙爜璁剧疆
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理及网络设置        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关
        </a>
        <a href="javascript:void(0)" onclick="openSourcesModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 7h8m-8 5h8m-8 5h5M6 3h12a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V5a2 2 0 012-2z" /></svg>
          源管理
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          閫€鍑?        </a>
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
          <span>鍏ㄧ綉澶囬€夎妭鐐规€绘暟</span>
        </div>
        <div class="stat-icon-wrapper">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
        </div>
      </div>
      <div class="stat">
        <div class="stat-info">
          <strong id="target">3</strong>
          <span>鐩爣浼橀€夎妭鐐规暟</span>
        </div>
        <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.2);">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--warning);"><path stroke-linecap="round" stroke-linejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
        </div>
      </div>
      <div class="stat">
        <div class="stat-info">
          <strong id="active">0</strong>
          <span>褰撳墠娲诲姩杩炴帴鏁?/span>
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
      <option value="">鎵€鏈夊浗瀹?/option>
    </select>
    <select id="ip_type_filter">
      <option value="">鎵€鏈塈P绫诲瀷</option>
      <option value="residential">浣忓畢IP</option>
      <option value="hosting">鏈烘埧IP</option>
    </select>
    <div class="protocol-filter-group">
      <span class="protocol-filter-title">灞曠ず鍗忚</span>
      <button type="button" id="list_protocol_tcp" class="protocol-toggle active" data-proto="tcp">TCP</button>
      <button type="button" id="list_protocol_udp" class="protocol-toggle active" data-proto="udp">UDP</button>
    </div>
    <input id="search" placeholder="杈撳叆鍥藉銆佷綅缃€両P銆丄SN銆佽繍钀ヤ富浣撶瓑杩囨护鑺傜偣..." />
    <button id="btn_batch_test" class="btn-primary" style="height: 42px; padding: 0 20px; font-weight: 600; background: var(--primary-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      鎵归噺娴嬭瘯鏈〉
    </button>
    <button id="btn_batch_test_all" class="btn-primary" style="height: 42px; padding: 0 20px; font-weight: 600; background: var(--success-gradient); margin-left: 12px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      鎵归噺娴嬭瘯鍏ㄩ儴
    </button>
  </section>
  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 110px;">鐘舵€?/th>
            <th style="width: 92px;">寤惰繜</th>
            <th style="width: 220px;">IP 鍦板潃 : 绔彛</th>
            <th style="width: 220px;">鐗╃悊浣嶇疆</th>
            <th style="width: 220px;">ASN</th>
            <th style="width: 180px;">杩愯惀涓讳綋 / ISP</th>
            <th style="width: 90px;">鍗忚</th>
            <th style="width: 110px;">缃戠粶璐ㄩ噺</th>
            <th style="width: 110px;">IP 绫诲瀷</th>
            <th style="width: 160px;">鎿嶄綔</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 鍒嗛〉鎺у埗鏍?-->
    <div class="pagination-container" style="padding: 16px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        鏄剧ず绗?<span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 鏉★紝鍏?<span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 鏉″閫夎妭鐐?      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">棣栭〉</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">涓婁竴椤?/button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          椤电爜 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">涓嬩竴椤?/button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">灏鹃〉</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (璐﹀彿瀵嗙爜璁剧疆) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          璐﹀彿瀵嗙爜璁剧疆
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="cred_username">鏂扮鐞嗚处鍙?/label>
          <input type="text" id="cred_username" class="input-field" required placeholder="璇疯緭鍏ユ柊绠＄悊璐﹀彿">
        </div>
        
        <div class="form-group" style="margin-bottom: 24px;">
          <label class="form-label" for="cred_password">鏂板畨鍏ㄥ瘑鐮?/label>
          <input type="password" id="cred_password" class="input-field" required placeholder="璇疯緭鍏ユ柊瀹夊叏瀵嗙爜">
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">鍙栨秷</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">淇濆瓨淇敼</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (浠ｇ悊鍙婄綉缁滆缃紝鍖呮嫭鍑虹珯璺敱) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          浠ｇ悊涓庣綉缁滆缃?        </h3>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="net_port">缃戦〉绠＄悊绔彛</label>
          <input type="number" id="net_port" class="input-field" required min="1" max="65535" placeholder="8787">
        </div>
        
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="net_suffix">鐧诲綍瀹夊叏鍚庣紑 (浠呭瓧姣嶅拰鏁板瓧)</label>
          <input type="text" id="net_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>

        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 浠ｇ悊鍑虹珯绔彛</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <div class="form-group" style="margin-bottom: 12px; margin-top: 16px;">
          <label class="form-label" for="net_proxy_user">SOCKS5 浠ｇ悊璐﹀彿 (鐣欑┖鍒欎笉楠岃瘉)</label>
          <input type="text" id="net_proxy_user" class="input-field" placeholder="璇疯緭鍏ヤ唬鐞嗚繛鎺ヨ处鍙?>
        </div>

        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_pass">SOCKS5 浠ｇ悊瀵嗙爜 (鐣欑┖鍒欎笉楠岃瘉)</label>
          <input type="text" id="net_proxy_pass" class="input-field" placeholder="璇疯緭鍏ヤ唬鐞嗚繛鎺ュ瘑鐮?>
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="net_routing_mode">IP 鍑虹珯璺敱妯″紡</label>
            <select id="net_routing_mode" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;" onchange="handleRoutingModeChange(this.value)">
              <option value="auto">鑷姩閰嶇疆 (鏅鸿兘鍒囨崲锛屾渶绋冲畾)</option>
              <option value="fixed_ip">鍥哄畾 IP (姘镐笉鑷姩鎹?IP)</option>
              <option value="fixed_region">鍥哄畾鍦板尯 (閿佸畾鐗瑰畾鍥藉鑺傜偣)</option>
            </select>
          </div>
          
          <div id="net_force_country_group" class="form-group" style="margin-bottom: 12px; display: none;">
            <label class="form-label" for="net_force_country">閿佸畾鍥藉鍦板尯</label>
            <select id="net_force_country" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">姝ｅ湪鍔犺浇鑺傜偣鍥藉...</option>
            </select>
          </div>
          
          <div id="net_routing_warning" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-top: 8px;">
            鈩癸笍 <strong>鑷姩閰嶇疆</strong>锛氬叏鑷姩娴嬭瘯骞堕€夋嫨鏈€浣矷P銆傚湪浣跨敤杩囩▼涓紝濡傛灉褰撳墠杩炴帴鑺傜偣娌℃湁澶辨晥锛屽皢涓嶅啀鏇存崲IP锛涘鏋滃綋鍓嶈妭鐐瑰け鏁堬紝绯荤粺灏嗙珛鍒荤绾ц嚜鍔ㄦ紓绉诲埌鍏朵粬鏈€蹇殑鍙敤鑺傜偣銆?          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">鍙栨秷</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">淇濆瓨淇敼</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Ad Modal (VPS 璐拱鎺ㄨ崘) -->
  <div id="ad_modal" class="modal">
    <div class="modal-content" style="max-width: 640px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--warning);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9.663 17h4.673M12 3v1m6.364.364l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /></svg>
          VPS 璐拱鎺ㄨ崘
        </h3>
        <button type="button" onclick="closeAdModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div class="ad-links" style="grid-template-columns: 1fr; gap: 16px;">
        <div class="ad-item">
          <span class="ad-tag tag-normal">鏅€氱敤鎴锋帹鑽?/span>
          <span class="ad-desc">RackNerd - 瓒呬綆鎶樻墸浠锋牸锛屾棩甯镐娇鐢ㄥ疄鎯犳柟渚匡紝娴峰澶氭満鎴垮彲閫夛紝鎺ㄨ崘鏅€氬搴垨浣庨鐢ㄦ埛銆?/span>
          <a href="https://my.racknerd.com/aff.php?aff=18708" target="_blank" class="ad-btn">鐐瑰嚮杩涘叆瀹樼綉</a>
        </div>
        <div class="ad-item">
          <span class="ad-tag tag-opt">缃戠粶浼樺寲鎺ㄨ崘</span>
          <span class="ad-desc">VMiss - 涓撶嚎浼樺寲缃戠粶 (CN2 GIA/9929/CMIN2 绛夐《绾х嚎璺?锛屼綆寤惰繜涓嶄涪鍖咃紝鎺ㄨ崘楂樼綉缁滆姹傜敤鎴枫€?/span>
          <a href="https://app.vmiss.com/aff.php?aff=4619" target="_blank" class="ad-btn">鐐瑰嚮杩涘叆瀹樼綉</a>
        </div>
        <div class="ad-item">
          <span class="ad-tag tag-premium">楂樼浼佷笟鎺ㄨ崘</span>
          <span class="ad-desc">BandwagonHost (鎼摝宸? - 鐩磋繛涓夌綉椤剁骇涓撶嚎锛岀粡鍏搁珮甯﹀ CN2 GIA 绾胯矾锛岃秴鍑＄ǔ瀹氶€熷害銆?/span>
          <a href="https://bandwagonhost.com/aff.php?aff=81790" target="_blank" class="ad-btn">鐐瑰嚮杩涘叆瀹樼綉</a>
        </div>
      </div>
      
      <div class="ad-footer" style="margin-top: 20px;">
        瀹樻柟鎶€鏈敮鎸佸強浼樿川璧勬簮浜ゆ祦璁哄潧锛?a href="https://339936.xyz" target="_blank" class="forum-link">339936.xyz</a>
      </div>

      <div class="ad-footer" style="margin-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px; text-align: left; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
        <div style="font-weight: bold; color: var(--text-primary); margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          馃巵 鎹愯禒鏀寔椤圭洰寮€鍙戯細
        </div>
        <div style="font-family: monospace; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 6px; margin-top: 6px; word-break: break-all; select-all: true;">
          <span style="color: var(--primary); font-weight: bold;">BNB (BSC):</span> 0xB6d78c42CEB0687A31B8cfEBE4b51b6eB8953C17<br>
          <span style="color: var(--primary); font-weight: bold;">TRX (TRC20):</span> TSdzCW6JvsrqcppodYjhSrku4mYmDJ9pxf
        </div>
      </div>
    </div>
  </div>

  <div class="vps-promo-tab" onclick="openAdModal()">VPS璐拱鎺ㄨ崘</div>

  <!-- Gateway Modal (缃戝叧鑷涓庝唬鐞嗘祴璇? -->
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
            鍑哄彛 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测          </button>
        </div>
      </div>
      
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">鍏抽棴</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (鏃ュ織鐩戞帶涓庡垎绫荤瓫閫? -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>
        
        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: rgba(255, 255, 255, 0.03);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">浠ｇ悊鐩稿叧 (Proxy)</option>
            <option value="vpn">VPN 杩炴帴 (VPN)</option>
            <option value="system">绯荤粺杩愯 (Main/Route)</option>
          </select>
        </div>
        
        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #a5b4fc; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
          <button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
            一键复制          </button>
          <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">鍏抽棴</button>
      </div>
    </div>
  </div>

  <div id="sources_modal" class="modal">
    <div class="modal-content" style="max-width: 860px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; gap: 12px; flex-wrap: wrap;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 7h8m-8 5h8m-8 5h5M6 3h12a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V5a2 2 0 012-2z" /></svg>
          API 源管理
        </h3>
        <button type="button" onclick="closeSourcesModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      <div id="sources_error" style="display:none; color: var(--danger); font-size: 13px; margin-bottom: 12px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px;"></div>
      <div id="sources_success" style="display:none; color: var(--success); font-size: 13px; margin-bottom: 12px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px;"></div>
      <div style="display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 14px;">
        <label style="display:flex; align-items:center; gap:8px; color: var(--text-primary); font-size:13px;">
          <input id="source_only_selected" type="checkbox" style="accent-color: #22c55e;">
          <span>只使用我勾选的源</span>
        </label>
        <button type="button" class="btn-primary" style="height: 36px; padding: 0 14px;" onclick="saveSourceSettings()">保存源策略</button>
        <button type="button" class="btn-primary" style="height: 36px; padding: 0 14px; background: rgba(255,255,255,0.06); color: var(--text-primary); border: 1px solid var(--border-color);" onclick="triggerSourceScan()">立即扫描源</button>
        <div id="sources_summary" style="margin-left:auto; font-size:12px; color: var(--text-secondary);"></div>
      </div>
      <form onsubmit="saveManualSource(event)" style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom: 14px;">
        <input id="manual_source_url" class="input-field" style="flex:1; min-width:320px;" placeholder="手动添加 API 源地址，例如 https://example.com/api/iphone/">
        <label style="display:flex; align-items:center; gap:8px; color: var(--text-primary); font-size:13px;">
          <input id="manual_source_selected" type="checkbox" style="accent-color: #22c55e;">
          <span>同时勾选</span>
        </label>
        <button type="submit" class="btn-primary" style="height: 40px; padding: 0 16px;">添加手动源</button>
      </form>
      <div style="max-height: 420px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 10px; background: rgba(255,255,255,0.02);">
        <table style="width: 100%;">
          <thead>
            <tr>
              <th style="width: 80px;">类型</th>
              <th>源地址</th>
              <th style="width: 90px;">状态</th>
              <th style="width: 80px;">失败</th>
              <th style="width: 150px;">最近成功</th>
              <th style="width: 170px;">操作</th>
            </tr>
          </thead>
          <tbody id="sources_rows">
            <tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--text-secondary);">正在加载源列表...</td></tr>
          </tbody>
        </table>
      </div>
      <div style="display:flex; justify-content:flex-end; margin-top: 16px;">
        <button type="button" onclick="closeSourcesModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">鍏抽棴</button>
      </div>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set(), sourcesData = [];
let currentPage = 1;
const pageSize = 15;
let currentPageNodes = [];

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"浠庢湭"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "鏅€?, "proxy": "浠ｇ悊", "datacenter": "鏁版嵁涓績", "mobile": "绉诲姩绔?};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "浣忓畢 IP", "hosting": "鏈烘埧 IP", "mobile": "绉诲姩缃?, "proxy": "浠ｇ悊 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
    "Japan": "鏃ユ湰",
    "Korea Republic of": "闊╁浗",
    "Korea": "闊╁浗",
    "Republic of Korea": "闊╁浗",
    "Thailand": "娉板浗",
    "United States": "缇庡浗",
    "United Kingdom": "鑻卞浗",
    "Russian Federation": "淇勭綏鏂?,
    "Russian": "淇勭綏鏂?,
    "Viet Nam": "瓒婂崡",
    "Vietnam": "瓒婂崡",
    "China": "涓浗",
    "Taiwan": "鍙版咕",
    "Taiwan Province of China": "鍙版咕",
    "Hong Kong": "棣欐腐",
    "Singapore": "鏂板姞鍧?,
    "Malaysia": "椹潵瑗夸簹",
    "Indonesia": "鍗板害灏艰タ浜?,
    "India": "鍗板害",
    "Philippines": "鑿插緥瀹?,
    "Australia": "婢冲ぇ鍒╀簹",
    "New Zealand": "鏂拌タ鍏?,
    "Canada": "鍔犳嬁澶?,
    "Ukraine": "涔屽厠鍏?,
    "France": "娉曞浗",
    "Germany": "寰峰浗",
    "Netherlands": "鑽峰叞",
    "Sweden": "鐟炲吀",
    "Norway": "鎸▉",
    "Spain": "瑗跨彮鐗?,
    "Turkey": "鍦熻€冲叾",
    "South Africa": "鍗楅潪",
    "Brazil": "宸磋タ",
    "Argentina": "闃挎牴寤?,
    "Chile": "鏅哄埄",
    "Mexico": "澧ㄨタ鍝?,
    "Egypt": "鍩冨強",
    "Romania": "缃楅┈灏间簹",
    "Poland": "娉㈠叞",
    "Kazakhstan": "鍝堣惃鍏嬫柉鍧?,
    "Georgia": "鏍奸瞾鍚変簹",
    "Mongolia": "钂欏彜",
    "Saudi Arabia": "娌欑壒闃挎媺浼?,
    "Iran": "浼婃湕",
    "Iraq": "浼婃媺鍏?,
    "Colombia": "鍝ヤ鸡姣斾簹",
    "Cambodia": "鏌煍瀵?,
    "Ireland": "鐖卞皵鍏?,
    "Italy": "鎰忓ぇ鍒?,
    "Switzerland": "鐟炲＋",
    "Belgium": "姣斿埄鏃?,
    "Austria": "濂ュ湴鍒?,
    "Denmark": "涓归害",
    "Finland": "鑺叞",
    "Portugal": "钁¤悇鐗?,
    "Greece": "甯岃厞",
    "Czech Republic": "鎹峰厠",
    "Hungary": "鍖堢墮鍒?,
    "Israel": "浠ヨ壊鍒?,
    "United Arab Emirates": "闃胯仈閰?,
    "UAE": "闃胯仈閰?,
    "Macao": "婢抽棬",
    "Macau": "婢抽棬",
    "Iceland": "鍐板矝",
    "Luxembourg": "鍗㈡．鍫?
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "鍙敤", "unavailable": "涓嶅彲鐢?, "not_checked": "寰呮娴?};
  return dict[s] || s || "寰呮娴?;
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
  
  select.innerHTML = '<option value="">鎵€鏈夊浗瀹?/option>' + 
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

function setSourcesNotice(type, message) {
  const errorEl = $("sources_error");
  const successEl = $("sources_success");
  if (errorEl) {
    errorEl.style.display = type === "error" && message ? "block" : "none";
    errorEl.textContent = type === "error" ? (message || "") : "";
  }
  if (successEl) {
    successEl.style.display = type === "success" && message ? "block" : "none";
    successEl.textContent = type === "success" ? (message || "") : "";
  }
}

function renderSourcesRows() {
  const tbody = $("sources_rows");
  const summary = $("sources_summary");
  if (!tbody) return;
  if (summary) {
    const healthy = sourcesData.filter(item => item.enabled && item.healthy).length;
    const queued = Number(state?.heavy_task_queued || 0);
    const running = state?.heavy_task_running ? `，当前任务：${state.heavy_task_running}` : "";
    summary.textContent = `总源 ${sourcesData.length} / 健康 ${healthy}${queued ? ` / 排队 ${queued}` : ""}${running}`;
  }
  if (!sourcesData.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--text-secondary);">当前还没有可管理的源</td></tr>`;
    return;
  }
  tbody.innerHTML = sourcesData.map(item => {
    const statusClass = item.healthy ? "available" : "unavailable";
    const statusText = item.healthy ? "健康" : "异常";
    const typeText = item.source_type === "manual" ? "手动" : (item.source_type === "official" ? "官方" : "自动");
    const canDelete = item.source_type === "manual";
    return `<tr>
      <td>${esc(typeText)}</td>
      <td class="mono" style="font-size: 12px; word-break: break-all;">${esc(item.url)}</td>
      <td><span class="badge ${statusClass}">${statusText}</span></td>
      <td>${Number(item.fail_count || 0)}</td>
      <td style="font-size: 12px;">${time(item.last_ok_at)}</td>
      <td>
        <div class="table-actions" style="gap: 6px; flex-wrap: wrap;">
          <label style="display:flex; align-items:center; gap:4px; font-size:12px; color: var(--text-secondary);">
            <input type="checkbox" ${item.enabled ? "checked" : ""} onchange="toggleSourceEnabled('${esc(item.id)}', this.checked)" style="accent-color: #22c55e;">
            <span>启用</span>
          </label>
          <label style="display:flex; align-items:center; gap:4px; font-size:12px; color: var(--text-secondary);">
            <input type="checkbox" ${item.selected ? "checked" : ""} onchange="toggleSourceSelected('${esc(item.id)}', this.checked)" style="accent-color: #22c55e;">
            <span>勾选</span>
          </label>
          ${canDelete ? `<button class="test-btn" onclick="deleteSource('${esc(item.id)}')">删除</button>` : ``}
        </div>
      </td>
    </tr>`;
  }).join("");
}

async function loadSources() {
  const response = await fetch("./api/sources");
  const data = await response.json();
  if (!data.ok) {
    throw new Error(data.error || "加载源列表失败");
  }
  sourcesData = Array.isArray(data.sources) ? data.sources : [];
  if (data.state) state = data.state;
  if ($("source_only_selected")) {
    $("source_only_selected").checked = Boolean(data.source_only_selected);
  }
  renderSourcesRows();
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
    alert("鍒楄〃灞曠ず璇疯嚦灏戜繚鐣欎竴绉嶅崗璁?);
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
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>姝ｅ湪杩炴帴</span>
              <strong>${esc(state.active_node_latency || '姝ｅ湪杩炴帴...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '姝ｅ湪涓?VPN 鑺傜偣寤虹珛鍔犲瘑闅ч亾锛岃绋嶅€?..')}
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
              <span class="badge available"><span class="badge-pulse"></span>宸茶繛鎺?/span>
              <strong>${esc(translateCountry(activeNode.country))} 鑺傜偣</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>鐗╃悊浣嶇疆: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">寤舵椂: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">杩愯惀涓讳綋: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 绫诲瀷: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
              <span style="margin-left: 12px;">鍗忚: <strong><span class="proto-badge ${esc(normalizeProtoLabel(activeNode.proto) || "udp")}">${esc(activeProto)}</span></strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          鏂紑杩炴帴
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
              <span class="badge unavailable" style="padding: 2px 8px;">鏈繛鎺?/span> 褰撳墠鏈繛鎺?VPN 鑺傜偣
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              鍦ㄤ笅鏂瑰垪琛ㄤ腑閫夋嫨涓€涓彲鐢ㄥ鐢ㄨ妭鐐瑰苟鐐瑰嚮 鈥滃垏鎹⑩€?鎸夐挳寮€濮嬭繛鎺ャ€?            </div>
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
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">鏃?/span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 浠ｇ悊鏈湴鎺ュ彛锛?{localProxy} | 娲诲姩鑺傜偣锛?{activeNodeInfo} | 鐘舵€侊細${statusMessage}`; }
  
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
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>姝ｅ湪杩炴帴`;
    pIpVal.textContent = state.active_node_latency || "姝ｅ湪杩炴帴...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "姝ｅ湪涓?VPN 鑺傜偣寤虹珛鍔犲瘑闅ч亾锛岃绋嶅€?..")}</span>`;
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
        pBadge.textContent = "鍙敤";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "涓嶅彲鐢?;
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "杩炴帴澶辫触")}</span>`;
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
    $("rows").innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的候选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>宸茶繛鎺? : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms}&nbsp;ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      const protoClass = normalizeProtoLabel(n.proto) || "udp";
      const protoText = formatProtoLabel(n.proto);
      
      const isTesting = testingNodeIds.has(n.id) || Boolean(n.is_testing);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}妫€娴嬩腑` : '妫€娴?;
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">宸茶繛鎺?/button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">鍒囨崲</button>`;
      
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
      alert("杩炴帴澶辫触: " + (result.error || "鏈煡閿欒"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("杩炴帴璇锋眰閿欒");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("纭畾瑕佹柇寮€褰撳墠鐨?VPN 杩炴帴鍚楋紵")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("鏂紑杩炴帴澶辫触: " + (result.error || "鏈煡閿欒"));
    }
  } catch (e) {
    alert("璇锋眰鏂紑杩炴帴澶辫触");
  }
}

// Batch test button implementation
$("btn_batch_test").onclick = async () => {
  const pageNodes = currentPageNodes || [];
  if (pageNodes.length === 0) {
    alert("褰撳墠椤甸潰娌℃湁鍙緵娴嬭瘯鐨勫閫夎妭鐐?);
    return;
  }
  
  const btn = $("btn_batch_test");
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width: 14px; height: 14px; display: inline-block; margin-right: 6px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>娴嬭瘯涓?..`;
  
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
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 鎵归噺娴嬭瘯鏈〉`;
  }
};

// ==========================================
// 鏂板锛氭壒閲忔祴璇曟墍鏈夎幏鍙栧埌鑺傜偣鐨勫疄鐜伴€昏緫
// ==========================================
$("btn_batch_test_all").onclick = async () => {
  const filteredNodes = getFilteredNodes();
  const filteredIds = filteredNodes.map(node => node.id).filter(Boolean);
  if (filteredIds.length === 0) {
    alert("褰撳墠绛涢€夌粨鏋滈噷娌℃湁鍙祴璇曠殑鑺傜偣銆?);
    return;
  }

  const btn = $("btn_batch_test_all");
  const originalHtml = btn.innerHTML;
  const chunkSize = 50;

  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width: 14px; height: 14px; display: inline-block; margin-right: 6px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>娴嬭瘯绛涢€夎妭鐐逛腑...`;

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
        console.error("鎵归噺娴嬭瘯绛涢€夎妭鐐瑰け璐?", e);
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
    selectCountry.innerHTML = '<option value="">鍏ㄩ儴</option>' + 
      countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  }
  
  // 2. Set value
  if (state.routing_mode === "fixed_ip") {
    if (!selectCountry.querySelector('option[value="fixed_ip_mode"]')) {
      const opt = document.createElement("option");
      opt.value = "fixed_ip_mode";
      opt.textContent = "鍥哄畾 IP 妯″紡";
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
    alert("璇疯嚦灏戝嬀閫変竴绉嶅崗璁?);
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
      alert("鏇存柊璺敱澶辫触: " + result.error);
    }
  } catch (e) {
    alert("鏇存柊鍑虹珯璺敱缃戠粶璇锋眰澶辫触");
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
  $("refresh").textContent="姝ｅ湪鍚庡彴鏇存柊..."; 
  try{await fetch("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="鏇存柊鑺傜偣";
  }, 3000);
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>娴嬭瘯涓?..`;
  badge.className = "badge not_checked";
  badge.textContent = "妫€娴嬩腑...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "鍙敤";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "涓嶅彲鐢?;
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">杩炴帴澶辫触</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "缃戠粶閿欒";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">璇锋眰鍑洪敊</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 娴嬭瘯浠ｇ悊`;
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
    warningDiv.innerHTML = `鈿狅笍 <strong>鍥哄畾鍦板尯</strong>锛氶檺鍒朵粎杩炴帴閫夊畾鍥藉鐨勮妭鐐癸紝涓斿悗鍙颁粎骞跺彂娴嬮€熻鍥藉鐨勮妭鐐广€傚鏋滆鍥界殑鎵€鏈夊彲鐢ㄨ妭鐐归兘澶辨晥锛屼細閫犳垚浠ｇ悊涓柇涓?strong>缁濅笉鑷姩鍒囨崲鍒板叾浠栧浗瀹?/strong>鐨勮妭鐐广€俙;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `鈿狅笍 <strong>鍥哄畾IP</strong>锛氶攣瀹氬綋鍓嶈繛鎺ョ殑鑺傜偣銆備笉绠¤鑺傜偣鏄惁澶辨晥锛岀郴缁熼兘缁濅笉鑷姩鍒囨崲鑷冲叾浠朓P锛涘鏋滆妭鐐圭敱浜庣綉缁滄晠闅滃け鏁堬紝浼氶€犳垚浠ｇ悊涓柇锛堜絾濡傛灉OpenVPN杩炴帴鎰忓閫€鍑猴紝鑴氭湰灏嗗皾璇曚负鎮ㄥ湪鍚庡彴閲嶆柊鎷夎捣杩炴帴鍚屼竴IP锛夈€?br><strong>鎻愮ず</strong>锛氭偍鍙互鍦ㄤ富椤?of 鑺傜偣鍒楄〃涓洿鎺ョ偣鍑烩€滆繛鎺モ€濇寜閽潵閫夋嫨骞堕攣瀹氫笉鍚岀殑IP鑺傜偣銆俙;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "rgba(255, 255, 255, 0.02)";
    warningDiv.style.border = "1px solid rgba(255, 255, 255, 0.05)";
    warningDiv.innerHTML = `鈩癸笍 <strong>鑷姩閰嶇疆</strong>锛氬叏鑷姩娴嬭瘯骞堕€夋嫨鏈€浣矷P銆傚湪浣跨敤杩囩▼涓紝濡傛灉褰撳墠杩炴帴鑺傜偣娌℃湁澶辨晥锛屽皢涓嶅啀鏇存崲IP锛涘鏋滃綋鍓嶈妭鐐瑰け鏁堬紝绯荤粺灏嗙珛鍒荤绾ц嚜鍔ㄦ紓绉诲埌鍏朵粬鏈€蹇殑鍙敤鑺傜偣銆俙;
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
  let html = '<option value="">璇烽€夋嫨瑕侀攣瀹氱殑鍥藉...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}涓妭鐐?</option>`;
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

function openSourcesModal() {
  setSourcesNotice("", "");
  $("admin_dropdown").style.display = "none";
  $("sources_modal").style.display = "flex";
  loadSources().catch(err => {
    setSourcesNotice("error", err?.message || "加载源列表失败");
  });
}

function closeSourcesModal() {
  $("sources_modal").style.display = "none";
}

async function saveSourceSettings() {
  setSourcesNotice("", "");
  try {
    const res = await fetch("./api/update_source_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source_only_selected: $("source_only_selected").checked
      })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "保存源设置失败");
    sourcesData = Array.isArray(data.sources) ? data.sources : sourcesData;
    renderSourcesRows();
    setSourcesNotice("success", data.message || "源设置已保存");
  } catch (err) {
    setSourcesNotice("error", err?.message || "保存源设置失败");
  }
}

async function saveManualSource(event) {
  event.preventDefault();
  setSourcesNotice("", "");
  const url = $("manual_source_url").value.trim();
  if (!url) {
    setSourcesNotice("error", "请输入手动源地址");
    return;
  }
  try {
    const res = await fetch("./api/source_upsert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        enabled: true,
        selected: $("manual_source_selected").checked
      })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "添加手动源失败");
    sourcesData = Array.isArray(data.sources) ? data.sources : sourcesData;
    $("manual_source_url").value = "";
    $("manual_source_selected").checked = false;
    renderSourcesRows();
    setSourcesNotice("success", data.message || "手动源已保存");
  } catch (err) {
    setSourcesNotice("error", err?.message || "添加手动源失败");
  }
}

async function updateSourceFlag(id, payload) {
  const res = await fetch("./api/source_update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, ...payload })
  });
  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || "更新源状态失败");
  sourcesData = Array.isArray(data.sources) ? data.sources : sourcesData;
  renderSourcesRows();
  setSourcesNotice("success", data.message || "源状态已更新");
}

async function toggleSourceEnabled(id, enabled) {
  setSourcesNotice("", "");
  try {
    await updateSourceFlag(id, { enabled });
  } catch (err) {
    setSourcesNotice("error", err?.message || "更新启用状态失败");
    loadSources().catch(() => {});
  }
}

async function toggleSourceSelected(id, selected) {
  setSourcesNotice("", "");
  try {
    await updateSourceFlag(id, { selected });
  } catch (err) {
    setSourcesNotice("error", err?.message || "更新勾选状态失败");
    loadSources().catch(() => {});
  }
}

async function deleteSource(id) {
  if (!confirm("确定删除这个手动源吗？")) return;
  setSourcesNotice("", "");
  try {
    const res = await fetch("./api/source_delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "删除源失败");
    sourcesData = Array.isArray(data.sources) ? data.sources : sourcesData;
    renderSourcesRows();
    setSourcesNotice("success", data.message || "源已删除");
  } catch (err) {
    setSourcesNotice("error", err?.message || "删除源失败");
  }
}

async function triggerSourceScan() {
  setSourcesNotice("", "");
  try {
    const res = await fetch("./api/source_scan", { method: "POST" });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "提交源扫描失败");
    sourcesData = Array.isArray(data.sources) ? data.sources : sourcesData;
    renderSourcesRows();
    setSourcesNotice("success", data.message || "源扫描任务已提交");
    setTimeout(() => {
      if ($("sources_modal").style.display === "flex") {
        loadSources().catch(() => {});
      }
    }, 3000);
  } catch (err) {
    setSourcesNotice("error", err?.message || "提交源扫描失败");
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
    errorDivEl.textContent = "鐢ㄦ埛鍚嶅拰瀵嗙爜涓嶈兘涓虹┖";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "姝ｅ湪淇濆瓨...";
  
  try {
    const res = await fetch("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      successDiv.textContent = "璐﹀彿瀵嗙爜淇濆瓨鎴愬姛锛屽凡鍗虫椂鐢熸晥锛?;
      successDiv.style.display = "block";
      setTimeout(() => {
        closeCredentialsModal();
        load();
      }, 1500);
    } else {
      errorDivEl.textContent = data.error || "淇濆瓨澶辫触锛岃妫€鏌ヨ緭鍏?;
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "淇濆瓨淇敼";
    }
  } catch (err) {
    errorDivEl.textContent = "杩炴帴鏈嶅姟鍣ㄥけ璐ワ紝璇风◢鍚庨噸璇?;
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "淇濆瓨淇敼";
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
    $("net_proxy_user").value = state.proxy_user || ""; // 鏂板杩欎竴琛?    $("net_proxy_pass").value = state.proxy_pass || ""; // 鏂板杩欎竴琛?  }
  
  populateRoutingCountries();
  $("network_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
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
  const proxyUser = $("net_proxy_user").value.trim(); // 鏂板杩欎竴琛?  const proxyPass = $("net_proxy_pass").value.trim(); // 鏂板杩欎竴琛?  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "缃戦〉绠＄悊绔彛鑼冨洿蹇呴』鍦?1 鑷?65535 涔嬮棿";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "浠ｇ悊鍑虹珯绔彛鑼冨洿蹇呴』鍦?1024 鑷?65535 涔嬮棿";
    errorDivEl.style.display = "block";
    return;
  }

  if (proxyPort === port) {
    errorDivEl.textContent = "浠ｇ悊鍑虹珯绔彛涓嶈兘涓庣綉椤电鐞嗙鍙ｇ浉鍚?;
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "鐧诲綍瀹夊叏鍚庣紑浠呰兘鐢辫嫳鏂囧瓧姣嶅拰鏁板瓧缁勬垚";
    errorDivEl.style.display = "block";
    return;
  }

  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "璇烽€夋嫨涓€涓閿佸畾鐨勭洰鏍囧浗瀹?;
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "姝ｅ湪淇濆瓨...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        port: port,
        secret_path: suffix,
        proxy_port: proxyPort,
        proxy_user: proxyUser, // 鏂板杩欎竴琛?        proxy_pass: proxyPass, // 鏂板杩欎竴琛?        routing_mode: routingMode,
        force_country: forceCountry
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "淇濆瓨鎴愬姛锛佺綉椤电鍙ｆ垨璺緞宸插彉鏇达紝椤甸潰灏嗗湪 4 绉掑唴鑷姩璺宠浆...";
        successDiv.style.display = "block";
        
        const inputs = $("network_form").querySelectorAll("input, button, select");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = "閰嶇疆淇濆瓨鎴愬姛锛屽凡鍗虫椂鐢熸晥锛?;
        successDiv.style.display = "block";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "淇濆瓨澶辫触锛岃妫€鏌ヨ緭鍏?;
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "淇濆瓨淇敼";
    }
  } catch (err) {
    errorDivEl.textContent = "杩炴帴鏈嶅姟鍣ㄥけ璐ワ紝璇风◢鍚庨噸璇?;
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "淇濆瓨淇敼";
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
    console.error("閫€鍑虹櫥褰曞け璐?, err);
    window.location.reload();
  }
}

// 椤甸潰鍔犺浇鏃惰嚜鍔ㄥ垵濮嬪寲鏁版嵁
load();

// 鍓嶅彴绌洪棽鏃惰嚜鍔ㄥ悓姝ヨ妭鐐逛笌鐘舵€侊紝寰呮娴嬪畬鎴愬悗浼氳嚜鍔ㄥ埛鏂板睍绀?setInterval(async () => {
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
    console.error("鍔犺浇缃戝叧鐘舵€佸け璐?, e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "姝ｅ湪杩愯" : "宸插仠姝?;
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
            鈿狅笍 璇婃柇鍘熷洜: ${esc(s.error)}
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
    console.error("鍔犺浇鏃ュ織澶辫触", e);
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
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">鏆傛棤璇ョ被鍨嬫棩蹇椼€?/div>`;
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
  if (!text || text.includes("鏆傛棤浠婃棩") || text.includes("鏆傛棤璇ョ被鍨?)) {
    alert("褰撳墠娌℃湁鍙緵澶嶅埗鐨勬棩蹇椼€?);
    return;
  }
  
  navigator.clipboard.writeText(text).then(() => {
    alert("鏃ュ織鍐呭宸叉垚鍔熷鍒跺埌鍓创鏉匡紒");
  }).catch(err => {
    console.error("澶嶅埗澶辫触", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("鏃ュ織鍐呭宸插鍒跺埌鍓创鏉匡紒");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("鏆傛棤浠婃棩") || text.includes("鏆傛棤璇ョ被鍨?)) {
    alert("褰撳墠娌℃湁鍙緵瀵煎嚭鐨勬棩蹇椼€?);
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
    # 1. 妫€娴嬩唬鐞嗘湇鍔＄鍙ｆ槸鍚﹀湪鐩戝惉
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
        diag_msg = diag[1] if diag else f"绔彛 {LOCAL_PROXY_PORT} 杩炴帴澶辫触锛屽師鍥? {e}"
        return {
            "ok": False,
            "error": f"浠ｇ悊鏈嶅姟鏈繍琛?({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 妫€娴嬭櫄鎷熺綉鍗?tun0 鏄惁瀛樺湪 (Linux 涓?
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[閿欒浠ｇ爜 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 铏氭嫙缃戝崱 (tun0) 鏈惎鐢紝璇风‘淇濆綋鍓嶅凡鎴愬姛杩炴帴 VPN 鑺傜偣"
        }

    # 3. 浣跨敤 curl 閫氳繃鏈湴 SOCKS5 浠ｇ悊鎺ュ彛娴嬭瘯 IP 涓庡疄闄呭欢杩?    ui_cfg = load_ui_config()
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
            
        # 姝ゆ椂澶栫綉娴嬭瘯澶辫触锛屾娴嬫湰鍦颁唬鐞嗙鍙ｆ槸鍚︿緷鐒惰兘杩為€氥€傝嫢浠嶈兘杩為€氾紝鐩存帴鎶涘嚭鍑哄彛娴嬭瘯澶辫触锛屼笉璋冪敤鍗犵敤璇婃柇
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
                return {"ok": False, "error": f"鍑哄彛杩炴帴娴嬭瘯澶辫触 | 鏈満璇婃柇缁撴灉: {diag[1]}"}
            
        return {"ok": False, "error": "鍑哄彛杩炴帴娴嬭瘯澶辫触 (ip.sb 鍜?api.ipify.org 鍧囨棤娉曡繛閫氾紝鍙兘鏄妭鐐瑰凡澶辨晥鎴?VPS 闃茬伀澧欓檺鍒朵簡 UDP/TCP 鍑虹珯绔彛)"}
    except Exception as e:
        return {"ok": False, "error": f"鍑哄彛杩炴帴娴嬭瘯寮傚父: {e}"}

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting, proxy_health_failures
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                proxy_health_failures = 0
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                log_to_json("INFO", "Proxy", f"浠ｇ悊鍙敤锛孖P: {res['ip']}, 寤惰繜: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "鏈煡閿欒")
                proxy_health_failures += 1
                if active_openvpn_node_id:
                    print(f"[璀﹀憡] {LOCAL_PROXY_PORT} 绔彛鏈湴浠ｇ悊褰撳墠涓嶅彲鐢紒鍘熷洜: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"浠ｇ悊涓嶅彲鐢?(杩炵画澶辫触 {proxy_health_failures}/{PROXY_HEALTH_FAILURE_THRESHOLD}): {error_msg}")
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
                                mark_blacklisted(active_node, f"浠ｇ悊杩為€氭€ф娴嬪け璐? {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[浠ｇ悊瀹堟姢绾跨▼] 鍥哄畾 IP 妯″紡涓嬩唬鐞嗕笉鍙敤锛屾鍦ㄥ皾璇曢噸鍚繛鎺ュ悓涓€鑺傜偣: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[浠ｇ悊瀹堟姢绾跨▼] 閲嶅惎鍥哄畾鑺傜偣澶辫触: {e}", flush=True)
        except Exception as e:
            print(f"[閿欒] 浠ｇ悊鍚庡彴妫€娴嬪彂鐢熷紓甯? {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"妫€娴嬪畧鎶ょ嚎绋嬪彂鐢熷紓甯? {e}")
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
                            set_state(active_node_latency="妫€娴嬭秴鏃?)
                    else:
                        set_state(active_node_latency="妫€娴嬭秴鏃?)
                else:
                    set_state(active_node_latency="妫€娴嬭秴鏃?)
            elif is_connecting:
                set_state(active_node_latency="娴嬭瘯涓?..")
            else:
                set_state(active_node_latency="鏃犳椿鍔ㄨ繛鎺?)
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
        elif effective_path == "/api/sources":
            self.send_json({"ok": True, **list_sources_payload(), "state": get_state()})
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
                "name": "Web 绠＄悊鏈嶅姟",
                "status": "running",
                "details": f"鐩戝惉鍦板潃: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
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
                proxy_err = diag[1] if diag else f"鏈湴浠ｇ悊缃戝叧鏃犳硶杩為€? {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "鏈湴浠ｇ悊缃戝叧",
                "status": "running" if proxy_ok else "stopped",
                "details": f"鐩戝惉鍦板潃: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "鏈繛鎺?
            if ovpn_ok:
                ovpn_details = f"宸茶繛鎺ヨ妭鐐? {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[璀﹀憡] 铏氭嫙缃戝崱 (tun0) 鏈惎鐢紝鍙兘瀛樺湪绛栫暐璺敱閰嶇疆闂銆?
            else:
                if active_openvpn_node_id:
                    ovpn_err = "杩炴帴宸蹭腑鏂垨 OpenVPN 鏍稿績绋嬪簭寮傚父閫€鍑恒€?
                    ovpn_details = f"灏濊瘯杩炴帴鑺傜偣 {active_openvpn_node_id} 澶辫触"
            openvpn_status = {
                "name": "OpenVPN 鏍稿績杩炴帴",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "鑺傜偣鍚屾瀹堟姢绾跨▼",
                "status": "running" if collector_ok else "stopped",
                "details": f"涓婃蹇冭烦: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '绛夊緟鍚姩'}",
                "error": "" if collector_ok else "绾跨▼鍙兘宸插紓甯哥粓姝紝瀵艰嚧鏃犳硶鍦ㄥ悗鍙版媺鍙栧拰娴嬮€熸柊鑺傜偣銆?
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "鍑哄彛妫€娴嬪畧鎶ょ嚎绋?,
                "status": "running" if checker_ok else "stopped",
                "details": f"涓婃蹇冭烦: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '绛夊緟鍚姩'}",
                "error": "" if checker_ok else "绾跨▼鍙兘宸叉寕璧锋垨缁堟锛屽鑷存棤娉曞疄鏃惰幏鍙栦唬鐞嗗嚭鍙ｇ姸鎬併€?
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "寤惰繜娴嬮€熷畧鎶ょ嚎绋?,
                "status": "running" if pinger_ok else "stopped",
                "details": f"涓婃蹇冭烦: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '绛夊緟鍚姩'}",
                "error": "" if pinger_ok else "绾跨▼鍙兘宸蹭腑姝紝鏃犳硶瀹炴椂鍒锋柊娲诲姩鑺傜偣鐨?Ping 寤惰繜銆?
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
                    self.send_json({"ok": False, "error": "鐢ㄦ埛鍚嶆垨瀵嗙爜涓嶆纭紝璇烽噸鏂拌緭鍏?}, HTTPStatus.FORBIDDEN)
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

        if effective_path == "/api/update_credentials":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                
                if not new_username or not new_password:
                    self.send_json({"ok": False, "error": "鐢ㄦ埛鍚嶅拰瀵嗙爜涓嶈兘涓虹┖"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                ui_cfg["username"] = new_username
                ui_cfg["password"] = new_password
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "璐﹀彿瀵嗙爜閰嶇疆鏇存柊鎴愬姛锛屽凡鍗虫椂鐢熸晥锛?})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/update_source_settings":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                ui_cfg = load_ui_config()
                ui_cfg["source_only_selected"] = bool(payload.get("source_only_selected", False))
                save_ui_config(ui_cfg)
                self.send_json({"ok": True, "message": "源设置已保存", **list_sources_payload()})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/source_upsert":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                source = upsert_source(
                    str(payload.get("url") or ""),
                    source_type="manual",
                    enabled=bool(payload.get("enabled", True)),
                    selected=bool(payload.get("selected", False)),
                )
                self.send_json({"ok": True, "message": "源已保存", "source": source, **list_sources_payload()})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/source_update":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                source_id = str(payload.get("id") or "").strip()
                if not source_id:
                    self.send_json({"ok": False, "error": "缺少源 ID"}, HTTPStatus.BAD_REQUEST)
                    return
                if not update_source_flags(
                    source_id,
                    enabled=payload.get("enabled") if "enabled" in payload else None,
                    selected=payload.get("selected") if "selected" in payload else None,
                ):
                    self.send_json({"ok": False, "error": "未找到该源"}, HTTPStatus.NOT_FOUND)
                    return
                self.send_json({"ok": True, "message": "源状态已更新", **list_sources_payload()})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/source_delete":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                source_id = str(payload.get("id") or "").strip()
                if not source_id:
                    self.send_json({"ok": False, "error": "缺少源 ID"}, HTTPStatus.BAD_REQUEST)
                    return
                if not delete_source(source_id):
                    self.send_json({"ok": False, "error": "未找到该源"}, HTTPStatus.NOT_FOUND)
                    return
                self.send_json({"ok": True, "message": "源已删除", **list_sources_payload()})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/source_scan":
            try:
                queued = request_source_scan()
                message = "已加入队列，后台会按顺序执行源扫描" if queued else "源扫描任务已在执行或排队中"
                self.send_json({"ok": True, "message": message, **list_sources_payload()})
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
                # 鏂板浠ヤ笅涓よ锛屾帴鏀跺墠绔綉椤典紶鏉ョ殑璐﹀彿鍜屽瘑鐮?                new_proxy_user = str(payload.get("proxy_user") or "").strip() 
                new_proxy_pass = str(payload.get("proxy_pass") or "").strip()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "绔彛鑼冨洿蹇呴』鏄?1 鑷?65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "浠ｇ悊鍑虹珯绔彛鑼冨洿蹇呴』鏄?1024 鑷?65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if new_proxy_port_int == new_port_int:
                    self.send_json({"ok": False, "error": "浠ｇ悊鍑虹珯绔彛涓嶈兘涓庣綉椤电鐞嗙鍙ｇ浉鍚?}, HTTPStatus.BAD_REQUEST)
                    return
                
                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "瀹夊叏鍚庣紑浠呰兘鐢辫嫳鏂囧瓧姣嶅拰鏁板瓧缁勬垚"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region"):
                    self.send_json({"ok": False, "error": "鏃犳晥鐨勮矾鐢遍厤缃ā寮?}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                ui_cfg["proxy_port"] = new_proxy_port_int
                # 鏂板浠ヤ笅涓よ锛屽啓鍏ラ厤缃枃浠?                ui_cfg["proxy_user"] = new_proxy_user 
                ui_cfg["proxy_pass"] = new_proxy_pass
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix or new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "閰嶇疆鏇存柊鎴愬姛锛岀郴缁熷強缃戦〉绔彛鎴栧悗缂€鍙樻洿锛屽皢鍦?2 绉掑唴閲嶅惎..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[绯荤粺] 绠＄悊鍚庡彴閰嶇疆鏇存柊锛岃繘绋嬪嵆灏嗛€€鍑轰互瑙﹀彂鑷姩閲嶅惎...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "message": "閰嶇疆鏇存柊鎴愬姛锛屽凡鍗虫椂鐢熸晥锛?})
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
                    self.send_json({"ok": False, "error": "鏃犳晥鐨勮矾鐢遍厤缃ā寮?}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "鏃犳晥鐨処P鍑虹珯绫诲瀷杩囨护"}, HTTPStatus.BAD_REQUEST)
                    return
                if not routing_protocol:
                    self.send_json({"ok": False, "error": "璇疯嚦灏戜繚鐣欎竴绉嶅崗璁?}, HTTPStatus.BAD_REQUEST)
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
                
                self.send_json({"ok": True, "message": "鍑虹珯璺敱閰嶇疆鏇存柊鎴愬姛锛屽凡鍗虫椂鐢熸晥锛?})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                if request_node_refresh(force=True, disconnect_active=True):
                    self.send_json({"ok": True, "message": "已加入队列，稍后按顺序执行强制节点更新"})
                else:
                    self.send_json({"ok": True, "message": "节点更新任务已在执行或排队中"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if request_node_refresh(force=False, disconnect_active=False):
                    self.send_json({"ok": True, "message": "已加入队列，后台会按顺序执行节点更新"})
                else:
                    self.send_json({"ok": True, "message": "节点更新任务已在执行或排队中"})
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
                set_state(active_openvpn_node_id="", last_check_message="鎵嬪姩鏂紑杩炴帴", active_node_latency="鏃犳椿鍔ㄨ繛鎺?)
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
                        proxy_error=result.get("error", "鏈煡閿欒")
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
    save_sources(load_sources())
    
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
    threading.Thread(target=run_heavy_task_queue, daemon=True).start()
    
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
        print("[网关] 代理网关已成功启动监听，开始同步与检测流程...", flush=True)
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

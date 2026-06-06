#!/usr/bin/env python3
from __future__ import annotations
import select
import socket
import threading
import urllib.parse
import time
import json        # [新增] 引入 json 库，用于读取保存账号密码的配置文件
import os          # [新增] 引入 os 库，用于处理文件路径
from pathlib import Path # [新增] 引入 Path，用于安全获取当前文件所在目录
from typing import Any

TUN_DEVICE = "tun0"
_tun_missing_log_lock = threading.Lock()
_tun_missing_last_log_at = 0.0
_throttled_log_lock = threading.Lock()
_throttled_log_state: dict[str, dict[str, float | int]] = {}

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    """辅助函数：确保从套接字中读取到指定大小的字节，防止数据断流"""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

# =====================================================================
# [新增] 读取代理验证信息的函数
# =====================================================================
def get_proxy_credentials():
    """
    读取保存在管理面板的 SOCKS5 代理账号和密码。
    这个函数会在每次有新客户端连接时被调用，所以你在网页后台修改密码后，
    不需要重启服务就能立即生效。
    """
    try:
        # 获取当前 proxy_server.py 文件所在目录，拼接出 ui_auth.json 的完整路径
        base_dir = Path(__file__).resolve().parent
        auth_file = base_dir / "vpngate_data" / "ui_auth.json"
        
        # 如果文件存在，就读取里面的 JSON 数据
        if auth_file.exists():
            data = json.loads(auth_file.read_text(encoding="utf-8"))
            # 返回字典中的 proxy_user 和 proxy_pass，如果没有就返回空字符串
            return data.get("proxy_user", ""), data.get("proxy_pass", "")
    except Exception:
        # 如果读取过程中发生任何错误（例如文件格式坏了），为了不让程序崩溃，直接忽略
        pass
    # 默认返回空，代表不需要密码验证
    return "", ""

def tun_device_ready() -> bool:
    return Path(f"/sys/class/net/{TUN_DEVICE}").exists()

def raise_tun_not_ready(prefix: str) -> None:
    global _tun_missing_last_log_at
    err = OSError(f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] {prefix} 绑定虚拟网卡 {TUN_DEVICE} 失败，找不到设备！")
    now = time.time()
    with _tun_missing_log_lock:
        if now - _tun_missing_last_log_at >= 5:
            _tun_missing_last_log_at = now
            print(f"[代理熔断] {err}", flush=True)
    raise err

def throttled_print(key: str, message: str, interval_seconds: float = 5.0) -> None:
    now = time.time()
    with _throttled_log_lock:
        state = _throttled_log_state.get(key)
        if state is None:
            _throttled_log_state[key] = {"last": now, "suppressed": 0}
            print(message, flush=True)
            return
        last = float(state.get("last", 0.0))
        suppressed = int(state.get("suppressed", 0))
        if now - last >= interval_seconds:
            suffix = f" [限流期间省略 {suppressed} 条同类日志]" if suppressed > 0 else ""
            _throttled_log_state[key] = {"last": now, "suppressed": 0}
            print(f"{message}{suffix}", flush=True)
            return
        state["suppressed"] = suppressed + 1

def resolve_dns_over_tun0(host: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
    """通过虚拟网卡 tun0 进行 DNS 解析，确保解析过程也走 VPN 隧道"""
    if not tun_device_ready():
        raise_tun_not_ready("DNS 解析")
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass

    import random
    tx_id = random.getrandbits(16).to_bytes(2, "big")
    flags = b"\x01\x00"
    questions = b"\x00\x01"
    rrs = b"\x00\x00\x00\x00\x00\x00"

    qname = b""
    for part in host.split("."):
        if not part:
            continue
        part_bytes = part.encode("idna")
        qname += len(part_bytes).to_bytes(1, "big") + part_bytes
    qname += b"\x00"

    qtype_qclass = b"\x00\x01\x00\x01"
    packet = tx_id + flags + questions + rrs + qname + qtype_qclass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
        except OSError as e:
            if "operation not permitted" in str(e).lower() or e.errno == 1:
                print("[DNS 绑定失败] [错误代码 3006] DNS 解析绑定 tun0 权限不足，请确保程序以 root 权限运行！", flush=True)
            elif "no such device" in str(e).lower() or e.errno == 19:
                print("[DNS 绑定失败] [错误代码 3004] DNS 解析绑定 tun0 失败，网卡设备不存在，请检查 VPN 连接！", flush=True)
            return None
        sock.sendto(packet, (dns_server, 53))
        resp, _ = sock.recvfrom(2048)
    except Exception:
        return None
    finally:
        sock.close()

    if len(resp) < 12:
        return None
    if resp[:2] != tx_id:
        return None

    rcode = resp[3] & 0x0F
    if rcode != 0:
        return None

    offset = 12
    while offset < len(resp):
        length = resp[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            offset += 2
            break
        else:
            offset += 1 + length

    offset += 4
    answers_count = int.from_bytes(resp[6:8], "big")
    if answers_count == 0:
        return None

    for _ in range(answers_count):
        if offset >= len(resp):
            break
        while offset < len(resp):
            length = resp[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                offset += 2
                break
            else:
                offset += 1 + length
        if offset + 10 > len(resp):
            break
        atype = int.from_bytes(resp[offset : offset + 2], "big")
        aclass = int.from_bytes(resp[offset + 2 : offset + 4], "big")
        rdlength = int.from_bytes(resp[offset + 8 : offset + 10], "big")
        offset += 10
        if offset + rdlength > len(resp):
            break
        if atype == 1 and aclass == 1 and rdlength == 4:
            ip_bytes = resp[offset : offset + 4]
            return socket.inet_ntoa(ip_bytes)
        offset += rdlength
    return None

def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    """创建前往目标的 TCP 连接，强制绑定 tun0 网卡实现透明代理"""
    if not tun_device_ready():
        raise_tun_not_ready("代理请求目标连接")
    host, port = address
    resolved_ip = resolve_dns_over_tun0(host)
    if resolved_ip:
        host = resolved_ip

    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if "operation not permitted" in str(e).lower() or e.errno == 1:
                err = OSError(f"[错误代码 3006] [ERR_PROXY_BIND_TUN_PERM_DENIED] 绑定虚拟网卡 tun0 失败，权限不足！必须以 root 权限运行。")
            elif "no such device" in str(e).lower() or e.errno == 19:
                err = OSError(f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] 绑定虚拟网卡 tun0 失败，找不到设备！")
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    else:
        raise OSError("getaddrinfo returns empty list")

def relay(left: socket.socket, right: socket.socket) -> None:
    """双向转发 TCP 数据流"""
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored:
            return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)

def socks5_udp_relay(tcp_client: socket.socket) -> None:
    """
    处理 SOCKS5 的 UDP ASSOCIATE (UDP 代理穿透) 逻辑
    Hysteria 2、Xray 等支持 UDP 代理的内核都需要依赖这个功能
    """
    udp_server = None
    outbound_udp = None
    try:
        if not tun_device_ready():
            raise_tun_not_ready("UDP 代理")
        local_ip = tcp_client.getsockname()[0]
        af = socket.AF_INET6 if ":" in local_ip else socket.AF_INET
        try:
            print(f"[SOCKS5 UDP] 客户端 {tcp_client.getpeername()} 发起 UDP ASSOCIATE", flush=True)
        except OSError:
            print("[SOCKS5 UDP] 收到 UDP ASSOCIATE 请求", flush=True)
        
        # 1. 创建本地 UDP 服务端监听客户端的 UDP 发包
        udp_server = socket.socket(af, socket.SOCK_DGRAM)
        udp_server.bind((local_ip, 0))
        bound_ip, bound_port = udp_server.getsockname()
        print(f"[SOCKS5 UDP] 已分配本地 UDP 中继端口 {bound_ip}:{bound_port}", flush=True)
        
        # 2. 将分配好的 IP 和 端口通过 TCP 应答告诉客户端
        # 【优化】修复 NAT 公网穿透。不返回绑定的内网 IP，而是返回 0.0.0.0
        # 这样 hy2 客户端就能聪明地复用主机的公网 IP 来发送 UDP 流量了。
        if af == socket.AF_INET:
            # 0.0.0.0 的字节表示为 \x00\x00\x00\x00
            reply = b"\x05\x00\x00\x01\x00\x00\x00\x00" + bound_port.to_bytes(2, "big")
        else:
            # :: 的字节表示为 16 个 \x00
            reply = b"\x05\x00\x00\x04" + (b"\x00" * 16) + bound_port.to_bytes(2, "big")
        tcp_client.sendall(reply)
        
        # 3. 创建负责跟外网目标通信的“出站 UDP”套接字
        outbound_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            outbound_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
        except OSError as e:
            print(f"[UDP绑定警告] 绑定 tun0 失败，流量可能未走 VPN: {e}", flush=True)
            pass
            
        sockets = [tcp_client, udp_server, outbound_udp]
        client_addr = None
        
        # 4. 进入 I/O 多路复用循环
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 120)
            if errored:
                break
                
            if tcp_client in readable:
                data = tcp_client.recv(256)
                if not data:
                    break 
                    
            if udp_server in readable:
                data, addr = udp_server.recvfrom(65536)
                client_addr = addr
                
                if len(data) < 10:
                    continue
                    
                frag = data[2]
                if frag != 0:
                    continue
                    
                atyp = data[3]
                offset = 4
                
                if atyp == 1:
                    dst_ip = socket.inet_ntoa(data[offset:offset+4])
                    offset += 4
                elif atyp == 3:
                    domain_len = data[offset]
                    offset += 1
                    dst_host = data[offset:offset+domain_len].decode("idna")
                    offset += domain_len
                    resolved_ip = resolve_dns_over_tun0(dst_host)
                    dst_ip = resolved_ip if resolved_ip else dst_host
                elif atyp == 4:
                    dst_ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                    offset += 16
                else:
                    continue
                    
                dst_port = int.from_bytes(data[offset:offset+2], "big")
                offset += 2
                
                payload = data[offset:]
                
                try:
                    outbound_udp.sendto(payload, (dst_ip, dst_port))
                except Exception:
                    pass
                    
            if outbound_udp in readable:
                data, addr = outbound_udp.recvfrom(65536)
                if not client_addr:
                    continue
                    
                src_ip, src_port = addr
                
                if ":" in src_ip:
                    header = b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, src_ip) + src_port.to_bytes(2, "big")
                else:
                    header = b"\x00\x00\x00\x01" + socket.inet_aton(src_ip) + src_port.to_bytes(2, "big")
                    
                try:
                    udp_server.sendto(header + data, client_addr)
                except Exception:
                    pass
                    
    except Exception as e:
        print(f"[UDP代理异常] 会话终止: {e}", flush=True)
    finally:
        if udp_server:
            try: udp_server.close()
            except: pass
        if outbound_udp:
            try: outbound_udp.close()
            except: pass

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    """
    SOCKS5 主控制逻辑
    """
    upstream = None
    try:
        # ==========================================
        # [修改] SOCKS5 握手认证阶段 (支持密码验证)
        # ==========================================
        # 1. 接收客户端支持的认证方式数量
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        # 2. 读取我们在网页后台配置的账号密码
        p_user, p_pass = get_proxy_credentials()
        
        # 3. 核心校验逻辑
        if p_user and p_pass:
            # 如果配置了账号密码，检查客户端（比如你的 hy2）是否支持密码认证 (协议代号为 2)
            if 2 not in methods:
                # \x05 代表 SOCKS5 协议，\xFF 代表拒绝（没有支持的认证方法）
                client.sendall(b"\x05\xFF") 
                return
            
            # 告诉客户端：你支持密码认证，请把账号密码发过来 (\x02 代表用户名密码认证)
            client.sendall(b"\x05\x02")
            
            # 开始接收客户端发来的账号密码数据包
            auth_version = recv_exact(client, 1)[0]
            if auth_version != 1:
                client.sendall(b"\x01\x01") # 版本不对，认证失败
                return
            
            # 解析客户端发来的用户名
            user_len = recv_exact(client, 1)[0]
            user = recv_exact(client, user_len).decode("utf-8")
            
            # 解析客户端发来的密码
            pass_len = recv_exact(client, 1)[0]
            password = recv_exact(client, pass_len).decode("utf-8")
            
            # 进行比对
            if user == p_user and password == p_pass:
                # 账号密码正确，返回 \x01\x00 (成功)
                client.sendall(b"\x01\x00") 
            else:
                # 账号密码错误，返回 \x01\x01 (失败) 并断开连接
                client.sendall(b"\x01\x01") 
                return
        else:
            # 如果后台留空了账号密码，就告诉客户端不需要认证 (协议代号为 0)
            client.sendall(b"\x05\x00")
        
        # ==========================================
        # 4. 认证成功后，继续接收客户端的连接请求
        # ==========================================
        version, command, _, address_type = recv_exact(client, 4)
        
        if version != 5 or command not in (1, 3):
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
            
        if address_type == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
            
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        if command == 1:
            try:
                upstream = create_connection((host, port), timeout=20)
            except Exception as e:
                throttled_print("socks5_connect_fail", f"[SOCKS5 代理失败] 目标 {host}:{port} 连接失败: {e}")
                try:
                    client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                except OSError:
                    pass
                raise
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(client, upstream)
            
        elif command == 3:
            try:
                print(f"[SOCKS5] 收到 UDP ASSOCIATE，请求源 {client.getpeername()}", flush=True)
            except OSError:
                print("[SOCKS5] 收到 UDP ASSOCIATE", flush=True)
            socks5_udp_relay(client)
            
    finally:
        client.close()
        if upstream:
            upstream.close()

def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    """读取 HTTP 代理请求头部"""
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def http_client(client: socket.socket, first_byte: bytes) -> None:
    """处理普通的 HTTP 代理请求 (注意：我们只给 SOCKS5 加了密码，HTTP代理暂不支持密码)"""
    upstream = None
    try:
        header = read_http_header(client, first_byte)
        head, rest = header.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            port = parse_int(port_text) or 443
            upstream = create_connection((host, port), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            relay(client, upstream)
            return

        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:"))]
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((parsed.hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception as e:
        throttled_print("http_connect_fail", f"[HTTP 代理失败] 代理请求目标连接失败: {e}")
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        client.close()
        if upstream:
            upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    """接收连接，根据客户端发送的第一个字节判断是 SOCKS5 还是 HTTP 代理"""
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\x05":
            socks5_client(client, first)
        else:
            http_client(client, first)
    except Exception as e:
        err_msg = str(e)
        if "[错误代码" in err_msg:
            throttled_print("proxy_client_fail", f"[代理客户端连接失败] 客户端 {address} 遭遇系统性阻碍: {err_msg}")
        try:
            client.close()
        except OSError:
            pass

def start_proxy_server(host: str, port: int) -> None:
    """启动代理服务器监听进程"""
    is_ipv6 = ":" in host or host == ""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    try:
        server = socket.socket(af, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if is_ipv6:
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        server.bind((host, port))
        server.listen(256)
        print(f"HTTP/SOCKS5 proxy listening on {host}:{port}", flush=True)
    except Exception as e:
        if is_ipv6 and host == "::":
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 0.0.0.0 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("0.0.0.0", port))
                server.listen(256)
                print(f"HTTP/SOCKS5 proxy listening on 0.0.0.0:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="0.0.0.0")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 0.0.0.0:{port}: {diag_msg}", flush=True)
                return
        elif is_ipv6 and host == "::1":
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 127.0.0.1 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", port))
                server.listen(256)
                print(f"HTTP/SOCKS5 proxy listening on 127.0.0.1:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="127.0.0.1")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 127.0.0.1:{port}: {diag_msg}", flush=True)
                return
        else:
            import vpn_utils
            diag = vpn_utils.diagnose_local_obstructions(port, host=host)
            diag_msg = diag[1] if diag else str(e)
            print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on {host}:{port}: {diag_msg}", flush=True)
            return

    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address), daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)

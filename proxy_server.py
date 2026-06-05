#!/usr/bin/env python3
from __future__ import annotations
import select
import socket
import threading
import urllib.parse
import time
from typing import Any

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def resolve_dns_over_tun0(host: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
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
                err = OSError(f"[错误代码 3006] [ERR_PROXY_BIND_TUN_PERM_DENIED] 绑定虚拟网卡 tun0 失败，权限不足！必须以 root 权限运行，或者进程缺少 CAP_NET_RAW 权限。")
            elif "no such device" in str(e).lower() or e.errno == 19:
                err = OSError(f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] 绑定虚拟网卡 tun0 失败，找不到设备！这通常是因为 OpenVPN 核心未能成功连接或已被异常终止。")
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    else:
        raise OSError("getaddrinfo returns empty list")

def relay(left: socket.socket, right: socket.socket) -> None:
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
        # 获取与客户端建立 TCP 连接的本地 IP，用于绑定 UDP 监听
        local_ip = tcp_client.getsockname()[0]
        af = socket.AF_INET6 if ":" in local_ip else socket.AF_INET
        
        # 1. 创建本地 UDP 服务端监听客户端的 UDP 发包
        udp_server = socket.socket(af, socket.SOCK_DGRAM)
        # 端口填 0 让操作系统自动分配一个闲置端口
        udp_server.bind((local_ip, 0))
        bound_ip, bound_port = udp_server.getsockname()
        
        # 2. 将分配好的 IP 和 端口通过 TCP 应答告诉客户端
        if af == socket.AF_INET:
            # 【优化】为了支持公网访问和 NAT 穿透，不要返回本地绑定的内网 IP (bound_ip)。
            # 我们直接返回 0.0.0.0，告诉 hy2 客户端直接使用与 TCP 握手相同的服务器公网 IP 发送 UDP 数据。
            reply = b"\x05\x00\x00\x01\x00\x00\x00\x00" + bound_port.to_bytes(2, "big")
        else:
            # 【优化】对于 IPv6 同理，返回全 0 的 :: 
            reply = b"\x05\x00\x00\x04" + (b"\x00" * 16) + bound_port.to_bytes(2, "big")
        tcp_client.sendall(reply)
        
        # 3. 创建负责跟外网目标通信的“出站 UDP”套接字
        outbound_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # 这一步极其关键，强制使 UDP 流量走 tun0 虚拟网卡 (即 VPN 隧道)
            outbound_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
        except OSError as e:
            # 如果尚未连接成功 tun0，给出提示但继续运行
            print(f"[UDP绑定警告] 绑定 tun0 失败，流量可能未走 VPN: {e}", flush=True)
            pass
            
        sockets = [tcp_client, udp_server, outbound_udp]
        client_addr = None # 用于缓存发起 UDP 请求的客户端真实地址
        
        # 4. 进入 I/O 多路复用循环，处理收发数据
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 120)
            if errored:
                break
                
            # 【TCP 断开监控】按照 SOCKS5 规范，如果客户端主动断开了主 TCP 握手连接，UDP 转发应当立即终止
            if tcp_client in readable:
                data = tcp_client.recv(256)
                if not data:
                    break 
                    
            # 【接收客户端 UDP 包】-> 拆除 SOCKS5 头部 -> 发送至真实外网目标
            if udp_server in readable:
                data, addr = udp_server.recvfrom(65536)
                client_addr = addr # 记录客户端地址，便于后续回传
                
                # 校验 SOCKS5 UDP 数据包长度
                if len(data) < 10:
                    continue
                    
                # 协议头部字段: RSV(2字节) | FRAG(1字节) | ATYP(1字节) | DST.ADDR | DST.PORT(2字节) | DATA
                frag = data[2]
                if frag != 0:
                    continue # 暂不支持 UDP 分片包处理
                    
                atyp = data[3]
                offset = 4
                
                # 提取目标 IP
                if atyp == 1: # IPv4
                    dst_ip = socket.inet_ntoa(data[offset:offset+4])
                    offset += 4
                elif atyp == 3: # 域名
                    domain_len = data[offset]
                    offset += 1
                    dst_host = data[offset:offset+domain_len].decode("idna")
                    offset += domain_len
                    # 强行通过 tun0 网卡进行 DNS 解析
                    resolved_ip = resolve_dns_over_tun0(dst_host)
                    dst_ip = resolved_ip if resolved_ip else dst_host
                elif atyp == 4: # IPv6
                    dst_ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                    offset += 16
                else:
                    continue
                    
                # 提取目标端口
                dst_port = int.from_bytes(data[offset:offset+2], "big")
                offset += 2
                
                # 剩余部分即为原始的用户数据负载
                payload = data[offset:]
                
                # 通过绑定的出口套接字发送到外网
                try:
                    outbound_udp.sendto(payload, (dst_ip, dst_port))
                except Exception:
                    pass
                    
            # 【接收外网目标响应数据】-> 拼接 SOCKS5 头部 -> 退回给客户端
            if outbound_udp in readable:
                data, addr = outbound_udp.recvfrom(65536)
                if not client_addr:
                    continue # 如果尚未记录客户端来源，则无法发回
                    
                src_ip, src_port = addr
                
                # 封装外网目标地址信息到 SOCKS5 头
                if ":" in src_ip:
                    header = b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, src_ip) + src_port.to_bytes(2, "big")
                else:
                    header = b"\x00\x00\x00\x01" + socket.inet_aton(src_ip) + src_port.to_bytes(2, "big")
                    
                # 连同真实数据发回客户端代理软件
                try:
                    udp_server.sendto(header + data, client_addr)
                except Exception:
                    pass
                    
    except Exception as e:
        print(f"[UDP代理异常] 会话终止: {e}", flush=True)
    finally:
        # 严谨的资源清理，防止端口泄露和挂起
        if udp_server:
            try: udp_server.close()
            except: pass
        if outbound_udp:
            try: outbound_udp.close()
            except: pass

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        # SOCKS5 握手认证阶段
        methods_count = recv_exact(client, 1)[0]
        recv_exact(client, methods_count)
        # 响应无需密码认证
        client.sendall(b"\x05\x00")
        
        # 接收客户端请求详情
        version, command, _, address_type = recv_exact(client, 4)
        
        # 仅支持 CONNECT (1) 和 UDP ASSOCIATE (3)
        if version != 5 or command not in (1, 3):
            # 发送指令不支持的错误码 (0x07)
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
            # [原逻辑] 处理传统的 TCP CONNECT 请求
            try:
                upstream = create_connection((host, port), timeout=20)
            except Exception as e:
                print(f"[SOCKS5 代理失败] 目标 {host}:{port} 连接失败: {e}", flush=True)
                try:
                    client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                except OSError:
                    pass
                raise
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(client, upstream)
            
        elif command == 3:
            # [新增] 将连接移交给 UDP 处理守护函数
            socks5_udp_relay(client)
            
    finally:
        client.close()
        if upstream:
            upstream.close()

def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def http_client(client: socket.socket, first_byte: bytes) -> None:
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
        print(f"[HTTP 代理失败] 代理请求目标连接失败: {e}", flush=True)
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        client.close()
        if upstream:
            upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
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
            print(f"[代理客户端连接失败] 客户端 {address} 遭遇系统性阻碍: {err_msg}", flush=True)
        try:
            client.close()
        except OSError:
            pass

def start_proxy_server(host: str, port: int) -> None:
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

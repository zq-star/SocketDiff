import socket
import threading
import json
import os
import ctypes
from ctypes import wintypes
from datetime import datetime
import sys
import signal
from socket_diagnostic_diff import SocketDiagnosticDiff
from collections import defaultdict
from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw
from scapy.config import conf
import time

# -------------------- WinSock 基础定义 --------------------
ws2_32 = ctypes.WinDLL("Ws2_32.dll")

ioctlsocket = ws2_32.ioctlsocket
ioctlsocket.argtypes = [wintypes.HANDLE, ctypes.c_long, ctypes.POINTER(wintypes.DWORD)]
ioctlsocket.restype  = ctypes.c_int

WSAGetLastError = ws2_32.WSAGetLastError
WSAGetLastError.restype = ctypes.c_int

FIONREAD = 0x4004667F  # 可读字节数（ioctlsocket）

# -------------------- 全局状态：仅抓取第一个连接 --------------------
first_conn = None              # 保存第一个连接的 socket
first_tag = None               # 第一个连接的 tag（ip_端口）
first_lock = threading.Lock()  # 保护 first_conn/first_tag 的并发访问

# 运行期控制
stop_event = threading.Event()    # 通知所有线程优雅退出
all_connections = set()           # 跟踪所有活动连接，方便统一关闭
all_threads = []                  # 跟踪处理线程，方便 join
all_lock = threading.Lock()

probe_data = b"DIAG_PROBE"  # 探测数据包内容
probe_timeout = 6.0         # 探测超时时间(秒)

class DiagnosticFileManager:
    def __init__(self):
        self.base_dir = os.path.abspath(f"output_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.raw_dir = os.path.join(self.base_dir, "raw_stats")
        self.diff_dir = os.path.join(self.base_dir, "diff_reports")
        
        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.diff_dir, exist_ok=True)

    def save_raw_stats(self, stats, tag):
        """保存原始诊断数据到raw_stats目录"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        safe_tag = tag.replace(":", "_").replace("/", "_")
        filename = f"stats_{timestamp}_{safe_tag}.json"
        path = os.path.join(self.raw_dir, filename)
        
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            return path
        except Exception as e:
            print(f"[diag] 写入原始数据失败: {e}")
            return None

# 初始化文件管理器
file_manager = DiagnosticFileManager()
diagnostic_diff = SocketDiagnosticDiff(file_manager.diff_dir)

# 在全局状态部分添加连接跟踪字典
connection_info = {}  # {socket对象: (源IP, 源端口, 目的IP, 目的端口)}
conn_info_lock = threading.Lock()

def track_connection(conn):
    with all_lock:
        all_connections.add(conn)
    # 获取并存储连接的四元组信息
    try:
        local_ip, local_port = conn.getsockname()
        remote_ip, remote_port = conn.getpeername()
        with conn_info_lock:
            connection_info[conn] = (remote_ip, remote_port, local_ip, local_port)
        print(f"[连接跟踪] 新连接: {remote_ip}:{remote_port} -> {local_ip}:{local_port}")
    except Exception as e:
        print(f"[连接跟踪] 获取四元组失败: {e}")

def untrack_connection(conn):
    with all_lock:
        all_connections.discard(conn)
    with conn_info_lock:
        if conn in connection_info:
            del connection_info[conn]

def track_thread(th):
    with all_lock:
        all_threads.append(th)

def set_first_connection(conn, tag):
    global first_conn, first_tag
    with first_lock:
        if first_conn is None:
            first_conn = conn
            first_tag = tag
            return True
        return False

def get_first_connection():
    with first_lock:
        return first_conn, first_tag

packet_state = defaultdict(lambda: {
    "src_ip": None,
    # "timestamp": None,
    "protocol": None,
    "length": 0
})  # key: (src_port, dst_port), value: 最新数据包信息

current_ports = (None, None)  # (src_port, dst_port)
current_protocol = None       # 当前协议类型
state_lock = threading.Lock()  # 保护全局状态的锁

# -------------------- Scapy抓包线程 --------------------
def start_packet_monitor(src_ip_filter=None):
    """启动后台抓包线程"""
    def _packet_callback(pkt):
        global current_ports, current_protocol

        if not (pkt.haslayer(IP) or pkt.haslayer(TCP) or pkt.haslayer(ICMP)):
            return
            
        # 检查目的IP是否为本地IP
        # local_ip = get_if_addr(conf.iface) if hasattr(conf, 'iface') else socket.gethostbyname(socket.gethostname())
        local_ip = "58.206.212.160"

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # 检查是否是目标IP与本地IP之间的通信（双向）
        is_src_to_local = (src_ip_filter and src_ip == src_ip_filter and dst_ip == local_ip)
        is_local_to_src = (src_ip_filter and src_ip == local_ip and dst_ip == src_ip_filter)
        
        # 如果指定了源IP过滤，但当前包不匹配双向通信，则忽略
        if src_ip_filter and not (is_src_to_local or is_local_to_src):
            return
        
        src_port, dst_port, protocol = 0, 0, "ICMP"  # 默认ICMP设置
        
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"
        elif pkt.haslayer(ICMP):
            # ICMP使用类型和代码作为伪端口
            src_port = pkt[ICMP].type
            dst_port = pkt[ICMP].code
            protocol = "ICMP"  

        print(f"[DEBUG] 端口信息 - 源端口: {src_port}, 目的端口: {dst_port}, 协议: {protocol}")          
            
        # 准备数据包信息
        pkt_info = {
            "src_ip": pkt[IP].src if pkt.haslayer(IP) else None,
            # "timestamp": pkt.time,
            "protocol": protocol, 
            # "length": len(pkt)
        }

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            # 获取IP标志位
            ip_flags = ip_layer.flags
            # 解析DF标志位
            df_flag = (ip_flags & 0x02) != 0  # DF标志是第2位
            mf_flag = (ip_flags & 0x01) != 0  # MF标志是第1位
            
            # 添加到pkt_info
            pkt_info.update({
                "ip_id": ip_layer.id,        # IP标识符（IPID）
                "ip_flags": int(ip_flags),  # 原始标志位值
                "df_flag": df_flag,         # Don't Fragment标志
                "mf_flag": mf_flag,         # More Fragments标志
                "fragment_offset": ip_layer.frag,  # 分片偏移量
                "ip_ttl": ip_layer.ttl,     # TTL值
                # "ip_tos": ip_layer.tos,     # TOS字段
            })
        
        # 更新全局状态
        with state_lock:
            packet_state[(src_port, dst_port, protocol)] = pkt_info
            current_ports = (src_port, dst_port)
            current_protocol = protocol

        print(f"抓包线程: {src_port}")

    # 启动抓包线程
    sniff_thread = threading.Thread(
        target=lambda: sniff(
            filter="ip or icmp",
            prn=_packet_callback,
            store=False
        ),
        daemon=True
    )
    sniff_thread.start()
    print(f"[抓包] 监控已启动，源IP过滤: {src_ip_filter or '无'}")

def get_packet_state(src_port, dst_port, protocol):
    """获取特定连接的状态"""
    with state_lock:
        return packet_state.get((src_port, dst_port, protocol), {})
        
def get_current_connection():
    global current_ports, current_protocol
    """获取当前活跃的连接信息"""
    with state_lock:
        return current_ports, current_protocol

def clear_current_connection():
    global current_ports, current_protocol
    """清空当前连接信息"""
    with state_lock:
        current_ports = (None, None)
        current_protocol = None
        print("[状态] 已清空当前连接记录")

def send_probe_and_capture(conn, tag):
    """
    发送探测数据包并捕获响应
    返回: (是否成功, 数据包信息)
    """
    
    try:
        # 获取连接的四元组信息
        with conn_info_lock:
            if conn in connection_info:
                src_ip, src_port, dst_ip, dst_port = connection_info[conn]
            else:
                return (False, {}, {"status": "error", "error": "connection info not found"})
        
        # 发送探测数据
        conn.send(probe_data)
        print(f"[probe] 已发送探测数据到 {src_ip}:{src_port}")
  
        # 等待响应
        start_time = time.time()
        while time.time() - start_time < probe_timeout:
            
            with state_lock:
                
                print(f"好玩22={dst_port}")
                print(f"好玩23={src_port}")
                print(f"好玩24={current_ports}")

                # current_ports, current_protocol = get_current_connection()
                # 检查是否有匹配当前连接的数据包到达
                if current_ports == (src_port, dst_port):
                    pkt_info_send = packet_state.get((current_ports[1] , current_ports[0], "TCP"), {})
                    pkt_info_rcv = packet_state.get((current_ports[0] , current_ports[1], "TCP"), {})
                    if pkt_info_rcv:
                        print(f"[probe] 捕获到响应数据包: {pkt_info_rcv}")
                        return (True, pkt_info_send, pkt_info_rcv)
            
            time.sleep(0.1)  # 避免忙等待
        
        # 超时未收到响应
        print(f"[probe] 探测超时，未收到响应")
        return (False, pkt_info_send, {"status": "timeout", "error": "no response received"})
    
    except Exception as e:
        print(f"[probe] 探测过程中出错: {e}")
        pkt_info_rcv = {
            "src_ip": "crash_error",
            "protocol": "crash_error",
            "length": "crash_error"
        }
        return (False, {}, pkt_info_rcv)

def collect_socket_diagnostics(sock: socket.socket, tag: str = "", trigger_info=None) -> None:
    stats = {}
    try:
        fd = sock.fileno()
    except Exception as e:
        print(f"[diag] 首连接已不可用: {e}")
        return

    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    base_tag = f"{tag}_{ts}" if tag else ts
    safe_tag = (
        base_tag.replace(":", "_")
                .replace("/", "_")
                .replace("\\", "_")
                .replace("*", "_")
                .replace("?", "_")
                .replace("|", "_")
                .replace("<", "_")
                .replace(">", "_")
                .replace("\"", "_")
    )

    # stats["capture_timestamp_local"] = ts

    def gs(level, opt, outtype=int, buflen=4):
        try:
            if outtype is int:
                return sock.getsockopt(level, opt)
            else:
                return sock.getsockopt(level, opt, buflen)
        except OSError as e:
            return f"ERROR({e})"

    # SOL_SOCKET
    stats["SO_TYPE"]       = gs(socket.SOL_SOCKET, socket.SO_TYPE)
    stats["SO_ERROR"]      = gs(socket.SOL_SOCKET, socket.SO_ERROR)
    stats["SO_RCVBUF"]     = gs(socket.SOL_SOCKET, socket.SO_RCVBUF)
    stats["SO_SNDBUF"]     = gs(socket.SOL_SOCKET, socket.SO_SNDBUF)
    stats["SO_KEEPALIVE"]  = gs(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
    stats["SO_REUSEADDR"]  = gs(socket.SOL_SOCKET, socket.SO_REUSEADDR)

    stats["IS_BLOCKING"] = sock.getblocking()
    stats["PROTOCOL_FAMILY"] = sock.family

    # SO_LINGER
    stats["SO_LINGER"] = None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 8)
        l_onoff  = int.from_bytes(raw[0:2], "little", signed=False)
        l_linger = int.from_bytes(raw[2:4], "little", signed=False)
        stats["SO_LINGER"] = {"l_onoff": l_onoff, "l_linger": l_linger}
    except OSError as e:
        stats["SO_LINGER"] = f"ERROR({e})"

    # TCP
    try:
        stats["TCP_NODELAY"] = gs(socket.IPPROTO_TCP, socket.TCP_NODELAY)
    except AttributeError:
        stats["TCP_NODELAY"] = "N/A"

    # FIONREAD
    try:
        arg = wintypes.DWORD(0)
        r = ioctlsocket(fd, FIONREAD, ctypes.byref(arg))
        stats["FIONREAD_bytes_available"] = int(arg.value) if r == 0 else f"ERROR({WSAGetLastError()})"
    except Exception as e:
        stats["FIONREAD_bytes_available"] = f"ERROR({e})"

    # 地址
    try:
        peer = sock.getpeername()
        stats["peername"] = {"host": peer[0], "port": peer[1]}
    except Exception as e:
        stats["peername"] = f"ERROR({e})"
    try:
        local = sock.getsockname()
        stats["sockname"] = {"host": local[0], "port": local[1]}
    except Exception as e:
        stats["sockname"] = f"ERROR({e})"

    # IP header fields
    try:
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        stats["IP_TTL"] = ttl
    except (OSError, AttributeError) as e:
        stats["IP_TTL"] = f"ERROR({e})"

    try:
        tos = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TOS)
        stats["IP_TOS"] = {
            "raw": tos,
            "DSCP": (tos >> 2) & 0x3F,  # 高6位
            "ECN": tos & 0x03          # 低2位
        }
    except (OSError, AttributeError) as e:
        stats["IP_TOS"] = f"ERROR({e})"

    return stats, tag

def collect_diagnostics(sock: socket.socket, tag: str = "", trigger_info=None) -> None:

    stats1, tag1 = collect_socket_diagnostics(sock, tag, trigger_info)
    clear_current_connection()
    success, pkt_info_send, pkt_info_rcv = send_probe_and_capture(sock, tag)
    # stats1["probe_info"] = {
        # "success": success,
        # "packet_info_send": pkt_info_send,
        # "packet_info_rcv": pkt_info_rcv
        # # "timestamp": datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    # }
    stats1["probe_success"] = success
    if isinstance(pkt_info_send, dict):
        for key, value in pkt_info_send.items():
            stats1[f"send_{key}"] = value
    else:
        stats1["send_info"] = pkt_info_send  # 如果不是字典，保持原样

    # 将 packet_info_rcv 的键值对展开到 stats1 顶级
    if isinstance(pkt_info_rcv, dict):
        for key, value in pkt_info_rcv.items():
            stats1[f"rcv_{key}"] = value
    else:
        stats1["rcv_info"] = pkt_info_rcv  # 如果不是字典，保持原样

    stats2, tag2 = collect_socket_diagnostics(sock, tag, trigger_info)
    # stats2["probe_info"] = stats1["probe_info"]

    stats2["probe_success"] = success
    if isinstance(pkt_info_send, dict):
        for key, value in pkt_info_send.items():
            stats2[f"send_{key}"] = value
    else:
        stats2["send_info"] = pkt_info_send

    if isinstance(pkt_info_rcv, dict):
        for key, value in pkt_info_rcv.items():
            stats2[f"rcv_{key}"] = value
    else:
        stats2["rcv_info"] = pkt_info_rcv

    clear_current_connection()
    # 写 JSON
    raw_path = file_manager.save_raw_stats(stats1, tag1)
    if raw_path:
        print(f"[diag] 原始诊断数据已保存: {raw_path}")

    diff_path = diagnostic_diff.compare_and_save(stats1, stats2, tag1, trigger_info)
    if diff_path:
        print(f"[diag] 发现变化，差异已保存至: {diff_path}")

# -------------------- 服务器逻辑（只抓首连接） --------------------
def handle_client(connection, client_address):
    global current_ports, current_protocol
    track_connection(connection)
    try:
        print(f"连接来自 {client_address}")
        tag = f"{client_address[0]}_{client_address[1]}"

        with conn_info_lock:
            if connection in connection_info:
                src_ip, src_port, dst_ip, dst_port = connection_info[connection]

        is_first = set_first_connection(connection, tag)
        if is_first:
            print("[diag] 首连接建立，立即采集")
            collect_diagnostics(connection, tag=tag, trigger_info={
                'type': 'initial',
                'client': client_address
            })

        # 给这个连接设置超时，避免永久阻塞在 recv()
        connection.settimeout(0.5)  # 500ms

        while not stop_event.is_set():
            try:
                if not is_first and (current_protocol == "ICMP" or current_ports ==(src_port, dst_port)):
                    prime_conn, prime_tag = get_first_connection()
                    if prime_conn is not None:
                        print("[diag] 非首连接收到数据，触发对首连接的再次采集")
                        try:
                            collect_diagnostics(prime_conn, tag=prime_tag, trigger_info={
                                'type': 'triggered',
                                'by_client': client_address,
                            })
                        except Exception as e:
                            print(f"[diag] 触发采集失败：{e}")
                        

                    else:
                        print("[diag] 无首连接可采集（可能已关闭）")
                        clear_current_connection()

                    


            except socket.timeout:
                # 周期性检查 stop_event
                continue
            except ConnectionResetError:
                print(f"连接被对端重置：{client_address}")
                break
            except OSError as e:
                print(f"连接错误 {client_address}: {e}")
                break

    finally:
        try:
            # 尽可能优雅关闭
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        finally:
            untrack_connection(connection)
            if get_first_connection()[0] is connection:
                # 如果首连接退出，把首连接清空
                with first_lock:
                    global first_conn, first_tag
                    first_conn = None
                    first_tag = None
        print(f"连接处理结束：{client_address}")

def start_server(host='0.0.0.0', port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 允许快速重用端口，避免“地址已在使用”
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    # accept 加超时，便于检查 stop_event
    server_socket.settimeout(0.5)

    print(f"正在启动服务器，地址：{host}:{port}")
    print("按回车键退出（或 Ctrl+C）...")

    def accept_loop():
        while not stop_event.is_set():
            try:
                connection, client_address = server_socket.accept()
                th = threading.Thread(target=handle_client, args=(connection, client_address), daemon=False)
                track_thread(th)
                th.start()
            except socket.timeout:
                continue
            except OSError as e:
                # 关闭 server_socket 后会到这里
                if stop_event.is_set():
                    break
                print(f"accept 出错：{e}")
                break
        print("接收线程退出。")

    accept_thread = threading.Thread(target=accept_loop, daemon=False)
    track_thread(accept_thread)
    accept_thread.start()

    # 支持 Ctrl+C
    def _sigint(_sig, _frm):
        print("\n收到中断信号，准备退出...")
        stop_event.set()
    signal.signal(signal.SIGINT, _sigint)

    # 主线程等待用户回车
    try:
        input()  # 按回车退出
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("开始优雅退出...")
        stop_event.set()

        # 关闭监听 socket，唤醒 accept()
        try:
            server_socket.close()
        except OSError:
            pass

        # 关闭所有活动连接，让 recv() 退出
        with all_lock:
            conns = list(all_connections)
        for c in conns:
            try:
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                c.close()
            except OSError:
                pass

        # 等待所有线程结束
        with all_lock:
            threads = [t for t in all_threads if t.is_alive()]
        for t in threads:
            t.join(timeout=2.0)

        print("服务器已退出。")

# -------------------- 入口 --------------------
if __name__ == "__main__":
    start_packet_monitor(src_ip_filter="58.206.202.54")
    start_server()

import socket
import time
import threading
import random
from scapy.all import sniff, IP, TCP, ICMP, Raw, send
from scapy.layers.inet import _IPOption_HDR
from collections import defaultdict

# 全局状态字典：{(local_ip, local_port, remote_ip, remote_port): {"last_ack": x, "last_seq": y, "last_len": z}}
tcp_state = defaultdict(lambda: {"last_ack": None, "last_seq": None, "last_len": 0})

icmp_payload = "A" * 300

def _sniff_and_update_state():
    """后台线程：持续嗅探并更新全局状态"""
    def _packet_callback(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload_len = len(bytes(pkt[Raw])) if pkt.haslayer(Raw) else 0

        # 提取四元组
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)

        # 更新对端发送的包（含ACK标志）
        if tcp.flags & 0x10:  # ACK标志
            tcp_state[key]["last_ack"] = tcp.ack

        # 更新对端发送的包的seq和长度（无论是否有ACK）
        tcp_state[key]["last_seq"] = tcp.seq
        tcp_state[key]["last_len"] = payload_len

    # 全局嗅探（过滤所有TCP流量）
    sniff(filter="tcp", prn=_packet_callback, store=False)

# 启动后台嗅探线程
sniff_thread = threading.Thread(target=_sniff_and_update_state, daemon=True)
sniff_thread.start()

def send_malformed_tcp_packet(
        sock,
        payload=b"MALFORMED TCP TEST",
        dscp=0,  # IP区分服务字段 (6 bits)
        ecn=0,   # IP显式拥塞通知 (2 bits)
        ip_id=None,  # IP标识
        df=False,    # 不分片标志
        mf=False,    # 更多分片标志
        frag_offset=0,  # 分片偏移
        tcp_flags="PA",  # TCP标志位
        tcp_window=8192,  # TCP窗口大小
        tcp_options=None,  # TCP选项
        tcp_seq=None,  # 序列号 (None表示自动计算)
        tcp_ack=None   # 确认号 (None表示自动计算)
    ):
    """发送变异的TCP包"""
    local_ip, local_port = sock.getsockname()
    remote_ip, remote_port = sock.getpeername()
    key = (remote_ip, remote_port, local_ip, local_port)

    # 从全局状态获取最新值
    state = tcp_state[key]
    
    # 自动计算序列号和确认号
    if tcp_seq is None:
        tcp_seq = state["last_ack"] if state["last_ack"] is not None else random.randint(0, 2**32-1)
    if tcp_ack is None:
        tcp_ack = (state["last_seq"] or 0) + (state["last_len"] or 0) if state["last_seq"] is not None else random.randint(0, 2**32-1)
    
    # 构造IP层
    ip = IP(
        src=local_ip,
        dst=remote_ip,
        tos=(dscp << 2) | ecn,  # 区分服务和ECN
        id=random.randint(0, 65535) if ip_id is None else ip_id,
        flags=(df << 1) | mf,  # DF和MF标志
        frag=frag_offset
    )
    
    # 构造TCP层
    tcp = TCP(
        sport=local_port,
        dport=remote_port,
        flags=tcp_flags,
        seq=tcp_seq,
        ack=tcp_ack,
        window=tcp_window,
        options=tcp_options or []
    )
    
    # 发送包
    pkt = ip / tcp / Raw(payload)
    send(pkt, verbose=False)
    print(f"[TCP] Sent malformed packet: seq={tcp_seq}, ack={tcp_ack}, flags={tcp_flags}, "
          f"tos={(dscp << 2) | ecn}, id={ip.id}, df={df}, mf={mf}, offset={frag_offset}")

def send_icmp_packet(
        sock,
        icmp_type=8,  # ICMP类型 (8=请求, 0=应答, 其他为差错报文)
        icmp_code=0,  # ICMP代码
        payload=b"ICMP TEST",
        dscp=0,       # IP区分服务字段
        ecn=0,        # IP显式拥塞通知
        ip_id=None    # IP标识
    ):
    """发送ICMP包"""
    local_ip, _ = sock.getsockname()
    remote_ip, _ = sock.getpeername()
    
    # 构造IP层
    ip = IP(
        src=local_ip,
        dst=remote_ip,
        tos=(dscp << 2) | ecn,
        id=random.randint(0, 65535) if ip_id is None else ip_id
    )
    
    # 构造ICMP层
    icmp = ICMP(
        type=icmp_type,
        code=icmp_code
    )
    
    # 发送包
    pkt = ip / icmp / Raw(payload)
    send(pkt, verbose=False)
    print(f"[ICMP] Sent packet: type={icmp_type}, code={icmp_code}, tos={(dscp << 2) | ecn}")

def generate_malformed_packets(sock):
    """生成并发送各种变异的TCP和ICMP包"""
    # TCP标志位组合
    tcp_flag_combinations = [
        "S",    # SYN
        "SA",   # SYN-ACK
        "R",    # RST
        "F",    # FIN
        "PA",   # PSH-ACK
        "U",    # URG
        "FA",   # FIN-ACK
        "RA",   # RST-ACK
        "",     # 无标志
        "SFPU"  # 所有标志
    ]
    
    # ICMP类型和代码组合 (常见类型)
    icmp_type_code_combinations = [
        (0, 0),   # Echo Reply
        (3, 0),   # Destination Unreachable - Net unreachable
        (3, 1),   # Destination Unreachable - Host unreachable
        (3, 2),   # Destination Unreachable - Protocol unreachable
        (3, 3),   # Destination Unreachable - Port unreachable
        (4, 0),   # Source Quench
        (5, 0),   # Redirect - Redirect for network
        (8, 0),   # Echo Request
        (11, 0),  # Time Exceeded - TTL expired in transit
        (12, 0)   # Parameter Problem
    ]
    
    # 发送变异的TCP包
    for flags in tcp_flag_combinations:
        send_malformed_tcp_packet(
            sock,
            payload=f"TCP TEST - flags {flags}".encode(),
            dscp=random.randint(0, 63),
            ecn=random.randint(0, 3),
            ip_id=random.randint(0, 65535),
            df=random.choice([True, False]),
            mf=random.choice([True, False]),
            frag_offset=random.randint(0, 8191),
            tcp_flags=flags,
            tcp_window=random.randint(1024, 65535)
        )
        time.sleep(8)
    
    # 发送各种ICMP包
    for icmp_type, icmp_code in icmp_type_code_combinations:
        send_icmp_packet(
            sock,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            payload=f"ICMP TEST - type {icmp_type} code {icmp_code}".encode(),
            ip_id=random.randint(0, 65535),
            dscp=random.randint(0, 63),
            ecn=random.randint(0, 3)
        )
        time.sleep(8)

if __name__ == "__main__":
    # 建立连接
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('58.206.212.160', 12345)
    try:
        client_socket.connect(server_address)
        print("Connected to server!")
        
        # 首次发送数据触发ACK
        client_socket.sendall(b"initial")
        time.sleep(8)  # 等待状态更新
        
        # 开始发送变异包
        '''
        while True:
            generate_malformed_packets(client_socket)
            time.sleep(8)  # 每轮发送间隔
        '''
        local_ip, _ = client_socket.getsockname()
        remote_ip, _ = client_socket.getpeername()
        send(IP(src=local_ip, dst=remote_ip) / ICMP(type=3, code=4, nexthopmtu=68) / IP(src=remote_ip, dst=local_ip) / ICMP(type=0, code=0) / icmp_payload, verbose = True)      
        # send(IP(src=local_ip, dst=remote_ip) / ICMP(type=4, code=0) / icmp_payload, verbose = True)     
    except Exception as e:
        print(f"Error: {e}")

# -*- coding: utf-8 -*-
from scapy.all import *
import random
import time
import threading
import json
import os
from datetime import datetime
from collections import defaultdict
from socket_diagnostic_diff_plc import SocketDiagnosticDiff


# ==================== 配置参数 ====================
target_ip = "192.168.1.201"  # 目标 IP 地址
local_ip = "192.168.1.32"
target_port = 102           # 目标端口
modbus_data = b'\x00\xaa\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a'
probe_timeout = 6.0
target_interface = "以太网 6"

class DiagnosticFileManager:
    def __init__(self):
        self.base_dir = os.path.abspath(f"plc_output_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
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

packet_state = defaultdict(dict)

current_ports = (None, None)  # (src_port, dst_port)
current_protocol = None       # 当前协议类型
state_lock = threading.RLock()  # 保护全局状态的锁


# -------------------- PLC回应包抓取线程 --------------------
def start_plc_response_monitor():
    """启动PLC回应包监控线程"""
    def _plc_response_callback(pkt):
        global current_ports, current_protocol, packet_state
        print(f"111111111")
        # 基本层检查
        if not pkt.haslayer(IP):
            return
            
        # 检查是否为PLC→client的数据包
        if pkt[IP].src != target_ip or pkt[IP].dst != local_ip:
            return
        
        print(f"22222222222")
        src_port, dst_port, protocol = 0, 0, "UNKNOWN"
        
        # TCP包处理
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport  # PLC端口
            dst_port = pkt[TCP].dport  # 客户端端口
            protocol = "TCP"
            ip_length = pkt[IP].len
            ip_header_length = pkt[IP].ihl * 4
            tcp_header_length = pkt[TCP].dataofs * 4
            payload_length = ip_length - ip_header_length - tcp_header_length
            
        # ICMP包处理  
        elif pkt.haslayer(ICMP):
            # ICMP使用类型和代码作为伪端口
            src_port = pkt[ICMP].type
            dst_port = pkt[ICMP].code
            protocol = "ICMP"
            payload_length = len(pkt[ICMP].payload) if pkt[ICMP].payload else 0
        else:
            return  # 只处理TCP和ICMP

        print(f"[PLC响应] 检测到{protocol}回应包 - {target_ip}:{src_port} -> {local_ip}:{dst_port}")          
            
        ipid = pkt[IP].id if pkt.haslayer(IP) else None
        # 准备数据包详细信息
        pkt_info = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": len(pkt),
            "ipid": ipid
        }
        
        # 添加协议特定信息
        if protocol == "TCP":
            pkt_info.update({
                "flags": str(pkt[TCP].flags),
                "seq": pkt[TCP].seq,
                "ack": pkt[TCP].ack,
                "window": pkt[TCP].window,
                "payload_length": payload_length
            })
        elif protocol == "ICMP":
            pkt_info.update({
                "type": pkt[ICMP].type,
                "code": pkt[ICMP].code
            })

        # 更新全局状态（只记录最近的一个数据包）
        with state_lock:
            # 更新当前数据包状态
            print(f"这里可以吗")
            packet_state[(src_port, dst_port, protocol)] = pkt_info
            current_ports = (src_port, dst_port)
            current_protocol = protocol
            print(f"[PLC响应] 数据包信息{packet_state}")


    # 构建BPF过滤器：只捕获从PLC发往客户端的TCP和ICMP包
    bpf_filter = f"(tcp or icmp) and src host {target_ip} and dst host {local_ip}"
    sniff(iface=target_interface, filter=bpf_filter, prn=_plc_response_callback, store=False)

    # 启动抓包线程
sniff_thread = threading.Thread(target=start_plc_response_monitor, daemon=True)
sniff_thread.start()
print(f"[PLC监控] PLC回应包监控已启动")
print(f"[PLC监控] 线程是否存活: {sniff_thread.is_alive()}")

# ==================== TCP连接函数 ====================
def connect_to_plc():
    """
    与PLC建立TCP连接的函数
    """
    # 生成随机参数
    src_port = random.randint(1024, 65535)
    init_seq = random.randint(0, 2**32 - 1)
    
    print(f"[*] 开始与PLC建立TCP连接: {target_ip}:{target_port}")
    
    # 步骤 1: 发送 SYN 包，开始建立连接
    syn = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S", seq=init_seq)
    syn_ack = sr1(syn)  # 发送 SYN 并等待回应 SYN+ACK

    print("[*] 发送 SYN，接收到回应 SYN+ACK")

    # 步骤 2: 发送 ACK 包，完成 TCP 握手
    syn_ack_ack = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(syn_ack_ack)  # 发送 SYN+ACK

    print("[*] 发送 ACK，完成 TCP 握手")
    
    # 返回连接信息
    return src_port, syn_ack_ack.seq, syn_ack_ack.ack

def get_current_plc_connection():
    """获取当前活跃的PLC连接信息"""
    global current_ports, current_protocol
    with state_lock:
        return current_ports, current_protocol

def get_packet_state(src_port, dst_port, protocol):
    """获取最新的PLC回应包信息"""
    with state_lock:
        print (f"数据包信息：{packet_state.get((src_port, dst_port, protocol), {})}")
        print (f"数据包信息：{dict(packet_state)}")
        return packet_state.get((src_port, dst_port, protocol), {})

def clear_plc_response_state():
    """清空PLC回应包状态"""
    global current_ports, current_protocol
    with state_lock:
        current_ports = (None, None)
        current_protocol = None
        print("[PLC监控] 已清空PLC回应包记录")

def get_all_plc_responses():
    """获取所有PLC回应包信息"""
    global packet_state
    with state_lock:
        return dict(packet_state)

# ==================== 探测数据包发送函数 ====================
def send_probe_modbus(src_port, dst_port, protocol):
    """发送探测Modbus/TCP数据包，直接从字典获取seq和ack"""
    try:
        # 直接从字典获取最新响应
        response_data = get_packet_state(dst_port, src_port, protocol)
        
        if not response_data:
            raise ValueError("字典中没有PLC响应数据")

        # 获取TCP序列信息
        if "seq" not in response_data or "ack" not in response_data:
            raise ValueError("响应数据中缺少TCP序列信息")
        
        # 使用PLC的确认号作为我们的序列号，PLC的序列号+1作为我们的确认号
        probe_seq = response_data["ack"]
        probe_ack = response_data["seq"] + response_data["payload_length"]
        
        
        print(f"[探测] 发送Modbus探测包")
        print(f"[探测] 源端口: {src_port} -> 目的端口: {dst_port}")
        print(f"[探测] 序列号: {probe_seq}, 确认号: {probe_ack}")
        
        # 构建Modbus探测包
        probe_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=probe_seq, ack=probe_ack) / Raw(modbus_data)
        
        clear_plc_response_state()

        send(probe_packet, verbose=0)
        print("[+] Modbus探测包发送成功")
        
        start_time = time.time()
        while time.time() - start_time < probe_timeout:
            with state_lock:
                # 检查是否有匹配的响应数据包到达
                print(f"3333333333333333")
                print(f"3333333333333333-{(dst_port, src_port)}")
                print(f"5555555555555555-{(current_ports)}")
                if current_ports == (dst_port, src_port):  # 注意端口顺序：PLC端口->客户端端口
                    pkt_info = get_packet_state(dst_port, src_port, "TCP")
                    print(f"444444444444444444444444")
                    if pkt_info:
                        print(f"[探测] 捕获到PLC响应数据包")
                        return (True, pkt_info)
            
            time.sleep(0.1)  # 避免忙等待
        
        # 超时未收到响应
        print(f"[探测] 探测超时，未收到PLC响应")
        return (False, {"status": "timeout", "error": "no response received"})
        
    except Exception as e:
        print(f"[探测] 探测过程中出错: {e}")
        pkt_info = {
            "src_ip": "error",
            "protocol": "error", 
            "length": "error",
            "error": str(e)
        }
        return (False, pkt_info)


def send_icmp_packet(
        src_ip,
        dst_ip,
        icmp_type=8,  # ICMP类型 
        icmp_code=0,  # ICMP代码
    ):
    """发送ICMP包"""
    
    # 构造IP层
    ip = IP(
        src=src_ip,
        dst=dst_ip
    )
    
    # 构造ICMP层
    icmp = ICMP(
        type=icmp_type,
        code=icmp_code
    )
    
    # 发送包
    pkt = ip / icmp / b"I'm a ping packet "
    send(pkt, verbose=False)
    print(f"[ICMP] Sent packet: type={icmp_type}, code={icmp_code}")

def generate_malformed_packets(src_ip,
        dst_ip):
    """生成并发送各种变异的ICMP包"""

    '''
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
    
    # 发送各种ICMP包
    for icmp_type, icmp_code in icmp_type_code_combinations:
        send_icmp_packet(
            src_ip,
            dst_ip,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            payload=f"ICMP TEST - type {icmp_type} code {icmp_code}".encode()
        )
        time.sleep(6)
    '''
    send_icmp_packet(
            src_ip,
            dst_ip,
            icmp_type=8,
            icmp_code=0
        )
    time.sleep(6)

def collect_diagnostics(success, pkt_info, tag, trigger_info):
    stats = pkt_info
    stats["success"] = success

    # 写 JSON
    raw_path = file_manager.save_raw_stats(stats, tag)
    if raw_path:
        print(f"[diag] 原始诊断数据已保存: {raw_path}")

    diff_path = diagnostic_diff.compare_and_save(stats, tag, trigger_info)
    if diff_path:
        print(f"[diag] 发现变化，差异已保存至: {diff_path}")

# ==================== 主函数 ====================
def main():
    """主函数"""
    print("开始执行PLC通信程序...")
    
    # 调用TCP连接函数
    v_src_port, v_seq_num, v_ack_num = connect_to_plc()
    victim_tag = f"{local_ip}_{v_src_port}"
    
    print(f"[+] TCP连接建立成功！源端口: {v_src_port}, 序列号: {v_seq_num}, 确认号: {v_ack_num}")
    
    
    print("\n[*] 发送探测Modbus包...")
    #probe_packet = IP(dst=target_ip) / TCP(sport=v_src_port, dport=target_port, flags="PA", seq=v_seq_num, ack=v_ack_num) / Raw(modbus_data)
    #send(probe_packet)
    success, pkt_info = send_probe_modbus(v_src_port, target_port, "TCP")
    collect_diagnostics(success, pkt_info, victim_tag, trigger_info={})

    generate_malformed_packets(local_ip, target_ip)
    success, pkt_info = send_probe_modbus(v_src_port, target_port, "TCP")
    collect_diagnostics(success, pkt_info, victim_tag, trigger_info={
                'protocol': 'ICMP',
                'icmp_type': 8, 
                'icmp_code': 0})
    
    print("程序执行完毕")

if __name__ == "__main__":
    main()
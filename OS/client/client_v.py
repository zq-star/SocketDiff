import socket
import time

def start_client1():
    """启动客户端1并与服务器通信"""
    # 创建TCP/IP套接字
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 连接到服务器
    server_address = ('58.206.212.160', 12345)
    client_socket.connect(server_address)
    
    print("已成功连接到服务器！")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    start_client1()

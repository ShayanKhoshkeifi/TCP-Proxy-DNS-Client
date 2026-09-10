#!/usr/bin/env python3

# Client - Sends messages to proxy server
# Authors: Georges Rizk (919388525), Shayan Khosh Keifi (923713063)

import socket
import json
import sys

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8000

# Server information (included in JSON sent to proxy)
SERVER_IP = "127.0.0.1"
SERVER_PORT = 7000

def recv_all(conn: socket.socket) -> str:
    chunks = []
    while True:
        data = conn.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")

def format_client_data_block(d: dict) -> str:
    return (
        "data = {\n"
        f'"server_ip": "{d.get("server_ip", "")}"\n'
        f'"server_port": {d.get("server_port", 0)}\n'
        f'"message": "{d.get("message", "")}"\n'
        "}"
    )

def main():
    # Check command line arguments
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <client_message>")
        print("Example: python3 client_[GeorgesRizk]_[ShayanKhoshKeifi].py Ping")
        sys.exit(1)
    
    msg = sys.argv[1]
    
    # Validate message is exactly 4 characters
    if len(msg) != 4:
        print("Error: <client_message> must be exactly 4 characters.")
        sys.exit(1)
    
    # Prepare JSON data
    data = {
        "server_ip": SERVER_IP,
        "server_port": SERVER_PORT,
        "message": msg
    }
    
    # Print what we're sending
    print("----------------------------")
    print("Sent to Proxy:")
    print("----------------------------")
    print(format_client_data_block(data))
    
    # Convert to JSON
    payload = json.dumps(data)
    
    # Connect to proxy and send message
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((PROXY_HOST, PROXY_PORT))
        client_socket.sendall(payload.encode("utf-8"))
        # Signal end of transmission
        client_socket.shutdown(socket.SHUT_WR)
        
        # Receive response from proxy
        reply = recv_all(client_socket).strip()
    
    # Print response
    print("----------------------------")
    print("Received from Proxy:")
    print("----------------------------")
    print(f'"{reply}"')

if __name__ == "__main__":
    main()
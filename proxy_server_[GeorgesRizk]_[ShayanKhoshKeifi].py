#!/usr/bin/env python3

# Proxy Server - Forwards messages between client and server
# Authors: Georges Rizk (919388525), Shayan Khosh Keifi (923713063)

import socket
import json
import sys

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8000

# IP Blocklist - customize as needed
BLOCKLIST = {
    "127.0.0.2",       # Local example
    "192.168.1.100",   # Private network example
    "10.0.0.50",       # Private network example
    "203.0.113.10",    # TEST-NET-3 example
    "198.51.100.77"    # TEST-NET-2 example
}

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
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind((PROXY_HOST, PROXY_PORT))
        proxy_socket.listen(5)
        
        print(f"[Proxy] Listening on {PROXY_HOST}:{PROXY_PORT}")
        
        while True:
            # Accept connection from client
            client_conn, client_addr = proxy_socket.accept()
            
            with client_conn:
                # Receive JSON from client
                raw = recv_all(client_conn).strip()
                
                # Parse JSON
                try:
                    client_data = json.loads(raw)
                except json.JSONDecodeError:
                    # Invalid JSON - send error
                    client_conn.sendall(b"Invalid JSON")
                    continue
                
                # Print received data
                print("----------------------------")
                print("Received from Client:")
                print("----------------------------")
                print(format_client_data_block(client_data))
                
                # Extract fields
                server_ip = client_data.get("server_ip", "")
                server_port = int(client_data.get("server_port", 0))
                message = str(client_data.get("message", ""))
                
                # Check blocklist
                if server_ip in BLOCKLIST:
                    reply = "Blocklist Error"
                    print("----------------------------")
                    print("Sent to Client:")
                    print("----------------------------")
                    print(f'"{reply}"')
                    client_conn.sendall(reply.encode("utf-8"))
                    continue
                
                # Forward message to server
                print("----------------------------")
                print("Sent to Server:")
                print("----------------------------")
                print(f'"{message}"')
                
                # Connect to server
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_conn:
                    server_conn.connect((server_ip, server_port))
                    server_conn.sendall(message.encode("utf-8"))
                    # Signal end of transmission
                    server_conn.shutdown(socket.SHUT_WR)
                    
                    # Receive response from server
                    server_reply = recv_all(server_conn).strip()
                
                # Print received response
                print("----------------------------")
                print("Received from Server:")
                print("----------------------------")
                print(f'"{server_reply}"')
                
                # Forward response to client
                print("----------------------------")
                print("Sent to Client:")
                print("----------------------------")
                print(f'"{server_reply}"')
                
                client_conn.sendall(server_reply.encode("utf-8"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Proxy] Shutting down.")
        sys.exit(0)
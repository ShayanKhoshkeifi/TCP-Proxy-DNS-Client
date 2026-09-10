#!/usr/bin/env python3

# Server - Responds to messages from proxy
# Authors: Georges Rizk (919388525), Shayan Khosh Keifi (923713063)

import socket
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 7000

def recv_all(conn: socket.socket) -> str:
    chunks = []
    while True:
        data = conn.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")

def compute_response(msg: str) -> str:
    msg = msg.strip()
    if msg == "Ping":
        return "Pong"
    if msg == "Pong":
        return "Ping"
    # Reverse any other string
    return msg[::-1]

def main():
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(5)
        
        print(f"[Server] Listening on {SERVER_HOST}:{SERVER_PORT}")
        
        while True:
            # Accept connection from proxy
            conn, addr = server_socket.accept()
            
            with conn:
                # Receive message from proxy
                incoming = recv_all(conn).strip()
                
                print("----------------------------")
                print("Received from Proxy:")
                print("----------------------------")
                print(f'"{incoming}"')
                
                # Compute response
                response = compute_response(incoming)
                
                print("----------------------------")
                print("Sent to Proxy:")
                print("----------------------------")
                print(f'"{response}"')
                
                # Send response back to proxy
                conn.sendall(response.encode("utf-8"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
        sys.exit(0)
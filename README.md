# TCP-Proxy-DNS-Client
Python implementation of a TCP proxy server architecture and iterative DNS client built from scratch using raw socket programming and RFC 1035 packet construction.

🌐 Proxy Server & DNS Client from Scratch

A Python networking project implementing two core internet infrastructure
components from scratch: a TCP proxy server architecture and an iterative
DNS resolver with raw packet construction and parsing.

---

🛠️ Technologies

- Python 3 – Core implementation language
- TCP Sockets – Client-proxy-server communication
- UDP Sockets – DNS query/response exchange
- JSON – Message formatting between client and proxy
- Python struct module – Raw DNS packet construction and parsing
- RFC 1035 – DNS protocol specification

---

✨ Features

- Proxy Server: Forwards messages between client and server with IP
  blocklist enforcement
- DNS Client: Iterative DNS resolution from root servers to authoritative
  nameservers entirely from scratch
- Raw Packet Construction: DNS query packets built manually using struct
  with no external DNS libraries
- DNS Compression: Supports DNS pointer compression in response parsing
- HTTP Request: After DNS resolution, performs a raw HTTP GET request to
  the resolved IP and reports the status line and RTT
- RTT Measurement: Round-trip time measured for every DNS query and the
  final HTTP request

---

📐 Part 1 – Proxy Server Architecture

The system consists of three independent Python programs running in
separate terminals:

| Component      | File                  | Port | Description                        |
|----------------|-----------------------|------|------------------------------------|
| Client         | client.py             | —    | Sends 4-character messages via JSON |
| Proxy Server   | proxy_server.py       | 8000 | Forwards messages, enforces blocklist|
| Server         | server.py             | 7000 | Processes messages and responds     |

Message Rules:
- "Ping" → returns "Pong"
- "Pong" → returns "Ping"
- Any other 4-character string → returns the string reversed

Blocklist: The proxy maintains a set of blocked IP addresses. If the
destination server IP is in the blocklist, the proxy returns a
"Blocklist Error" to the client without forwarding the message.

---

📐 Part 2 – DNS Client from Scratch

The DNS client performs fully iterative resolution starting from the
13 root servers, following NS referrals through TLD servers to
authoritative nameservers, until the final A record is obtained.

Resolution Flow:
1. Start with a root server (a.root-servers.net through m.root-servers.net)
2. Send a DNS query packet built manually using struct
3. Parse the response — extract A records, NS records, CNAME records,
   and glue records from the additional section
4. If NS referral received, use glue IPs if available; otherwise
   recursively resolve the NS hostname to get its IP
5. Repeat until the final A record is found
6. Make a raw HTTP GET request to the resolved IP on port 80

DNS Packet Structure:
- Header: 12 bytes containing transaction ID, flags, and section counts
- Question: QNAME encoded in DNS wire format, QTYPE, QCLASS
- Transaction ID randomly generated per query
- Recursion Desired flag set to 0 to force iterative resolution

---

🚀 How to Run

Part 1 – Proxy Server (open 3 terminals):

Terminal 1 – Start the server:
python3 server.py

Terminal 2 – Start the proxy:
python3 proxy_server.py

Terminal 3 – Run the client:
python3 client.py Ping
python3 client.py Pong
python3 client.py abcd

Part 2 – DNS Client:
python3 DNS_client.py wikipedia.org

---

💡 What I Learned

- TCP Socket Programming: Implementing reliable message framing using
  a recv_all() helper to handle stream fragmentation at the byte level
- DNS Protocol Internals: Constructing and parsing DNS packets manually
  using struct, including DNS wire format name encoding and compression
  pointer handling
- Iterative DNS Resolution: Following the full referral chain from root
  servers to TLD to authoritative nameservers without relying on any
  resolver library
- Network Debugging: Diagnosing TCP stream issues where a single recv()
  call does not guarantee receipt of the full message
- RTT Measurement: Using high-resolution timers to measure per-query
  and per-request round-trip times

---

👥 Contributors

Shayan Khosh Keifi — TCP socket implementation, DNS packet construction
and parsing, iterative resolver logic, HTTP request, debugging and testing

George Rizk — Proxy server architecture, blocklist logic, output
formatting, testing and verification

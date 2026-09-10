#!/usr/bin/env python3

# DNS Client - Iterative DNS Resolution from Scratch
# Authors: Georges Rizk (919388525), Shayan Khosh Keifi (923713063)

import random
import socket
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

# Root servers (IPv4 addresses from A through M)
ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "170.247.170.2",  # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
    "192.5.5.241",    # f.root-servers.net
    "192.112.36.4",   # g.root-servers.net
    "198.97.190.53",  # h.root-servers.net
    "192.36.148.17",  # i.root-servers.net
    "192.58.128.30",  # j.root-servers.net
    "193.0.14.129",   # k.root-servers.net
    "199.7.83.42",    # l.root-servers.net
    "202.12.27.33",   # m.root-servers.net
]

# DNS record type codes
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_AAAA = 28
CLASS_IN = 1

# Timeout for UDP queries (10 seconds per spec)
UDP_TIMEOUT_SEC = 10


# DNS Name Encoding
def encode_qname(domain: str) -> bytes:
    domain = domain.strip(".")
    parts = domain.split(".") if domain else []
    out = b""
    for part in parts:
        label = part.encode("utf-8")
        if len(label) > 63:
            raise ValueError("DNS label too long")
        out += bytes([len(label)]) + label
    out += b"\x00"  # Null terminator
    return out

# DNS Packet Construction
def build_dns_query(domain: str, qtype: int = TYPE_A) -> Tuple[int, bytes]:
    # Generate random transaction ID
    tid = random.randint(0, 0xFFFF)
    
    # Flags: Standard query, RD=0 (no recursion - we want referrals)
    flags = 0x0000
    
    # Counts: 1 question, 0 answers/authority/additional
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    
    # Build header (12 bytes)
    header = struct.pack(">HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)
    
    # Build question section
    qname = encode_qname(domain)
    question = qname + struct.pack(">HH", qtype, CLASS_IN)
    
    return tid, header + question

# DNS Name Decoding (handles compression)
def decode_name(msg: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original_next = offset
    
    while True:
        if offset >= len(msg):
            return ("", offset)
        
        length = msg[offset]
        
        # Compression pointer: 11xxxxxx xxxxxxxx
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(msg):
                return ("", offset + 1)
            ptr = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                original_next = offset + 2
                jumped = True
            offset = ptr
            continue
        
        # End of name
        if length == 0:
            offset += 1
            if not jumped:
                original_next = offset
            break
        
        # Regular label
        offset += 1
        if offset + length > len(msg):
            return ("", offset + length)
        
        label = msg[offset:offset + length].decode("utf-8", errors="replace")
        labels.append(label)
        offset += length
        
        if not jumped:
            original_next = offset
    
    return ".".join(labels), original_next

# DNS Resource Record Parsing
def type_to_str(t: int) -> str:
    return {
        TYPE_A: "A",
        TYPE_AAAA: "AAAA",
        TYPE_NS: "NS",
        TYPE_CNAME: "CNAME",
    }.get(t, f"TYPE{t}")


def parse_rr(msg: bytes, offset: int) -> Tuple[Dict, int]:
    # Decode name
    name, offset = decode_name(msg, offset)
    
    if offset + 10 > len(msg):
        return ({"name": name}, len(msg))
    
    # Parse fixed fields
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[offset:offset + 10])
    offset += 10
    
    # Extract RDATA
    rdata_start = offset
    rdata_end = min(len(msg), offset + rdlen)
    raw = msg[rdata_start:rdata_end]
    offset = rdata_end
    
    # Decode RDATA based on type
    decoded = None
    if rtype == TYPE_A and len(raw) == 4:
        decoded = socket.inet_ntoa(raw)
    elif rtype == TYPE_AAAA and len(raw) == 16:
        decoded = socket.inet_ntop(socket.AF_INET6, raw)
    elif rtype in (TYPE_NS, TYPE_CNAME):
        decoded, _ = decode_name(msg, rdata_start)
    else:
        decoded = raw.hex()
    
    return {
        "name": name,
        "type": rtype,
        "type_str": type_to_str(rtype),
        "class": rclass,
        "ttl": ttl,
        "rdlen": rdlen,
        "rdata": decoded,
    }, offset


def parse_dns_response(msg: bytes) -> Dict:
    if len(msg) < 12:
        return {}
    
    # Parse header
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", msg[:12])
    rcode = flags & 0x000F
    
    offset = 12
    
    # Parse questions
    questions = []
    for _ in range(qdcount):
        qname, offset = decode_name(msg, offset)
        if offset + 4 > len(msg):
            break
        qtype, qclass = struct.unpack(">HH", msg[offset:offset + 4])
        offset += 4
        questions.append({"qname": qname, "qtype": qtype, "qclass": qclass})
    
    # Parse answers
    answers = []
    for _ in range(ancount):
        rr, offset = parse_rr(msg, offset)
        answers.append(rr)
    
    # Parse authority
    authority = []
    for _ in range(nscount):
        rr, offset = parse_rr(msg, offset)
        authority.append(rr)
    
    # Parse additional
    additional = []
    for _ in range(arcount):
        rr, offset = parse_rr(msg, offset)
        additional.append(rr)
    
    return {
        "tid": tid,
        "flags": flags,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "questions": questions,
        "answers": answers,
        "authority": authority,
        "additional": additional,
    }

# UDP Exchange with RTT
def dns_exchange(server_ip: str, domain: str, qtype: int = TYPE_A) -> Tuple[Optional[Dict], Optional[float]]:
    tid, packet = build_dns_query(domain, qtype=qtype)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_TIMEOUT_SEC)
    
    start = time.perf_counter()
    try:
        sock.sendto(packet, (server_ip, 53))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError):
        return None, None
    finally:
        sock.close()
    
    rtt_ms = (time.perf_counter() - start) * 1000.0
    resp = parse_dns_response(data)
    
    return resp, rtt_ms

# Output Formatting (matches spec exactly)
def print_query_block(server_ip: str, domain: str, resp: Dict, rtt_ms: float) -> None:
    """Print query results in required format"""
    print("--------------------------------------------")
    print(f"Querying {server_ip} for {domain}")
    print("--------------------------------------------")
    
    def print_rrs(rrs: List[Dict]) -> None:
        for rr in rrs:
            t = rr.get("type_str", "TYPE?")
            val = rr.get("rdata", "")
            if val:
                print(f"{t} : {val}")
    
    print_rrs(resp.get("answers", []))
    print_rrs(resp.get("authority", []))
    print_rrs(resp.get("additional", []))
    
    print(f"RTT: {int(round(rtt_ms))} ms")

# Helper Functions for Iterative Resolution
def extract_answer_a(resp: Dict) -> List[str]:
    return [
        rr["rdata"] for rr in resp.get("answers", [])
        if rr.get("type") == TYPE_A and isinstance(rr.get("rdata"), str)
    ]


def extract_cname(resp: Dict) -> Optional[str]:
    for rr in resp.get("answers", []):
        if rr.get("type") == TYPE_CNAME and isinstance(rr.get("rdata"), str):
            return rr["rdata"]
    return None


def extract_ns_names(resp: Dict) -> List[str]:
    return [
        rr["rdata"] for rr in resp.get("authority", [])
        if rr.get("type") == TYPE_NS and isinstance(rr.get("rdata"), str)
    ]


def glue_ips_for_ns(resp: Dict, ns_names: List[str]) -> List[str]:
    ips: List[str] = []
    ns_set = set(n.lower().strip(".") for n in ns_names)
    for rr in resp.get("additional", []):
        if rr.get("type") == TYPE_A and isinstance(rr.get("rdata"), str):
            rrname = rr.get("name", "").lower().strip(".")
            if rrname in ns_set:
                ips.append(rr["rdata"])
    return ips


def resolve_nameserver_ip(ns_name: str) -> Optional[str]:
    ips = iterative_resolve_a(ns_name, print_steps=False)
    return ips[0] if ips else None


# Main Iterative Resolver
def iterative_resolve_a(domain: str, print_steps: bool = True) -> List[str]:
    target = domain.strip(".")
    max_hops = 25
    
    # Start with root servers
    servers = ROOT_SERVERS[:]
    
    for _hop in range(max_hops):
        resp = None
        rtt = None
        used_server = None
        
        # Try servers in list (with 10 second timeout each)
        for sip in servers:
            resp, rtt = dns_exchange(sip, target, qtype=TYPE_A)
            if resp is not None and rtt is not None:
                used_server = sip
                break
        
        if resp is None:
            # All servers timed out
            return []
        
        if print_steps:
            print_query_block(used_server, domain, resp, rtt)
        
        # Check for A record answer (done!)
        answers = extract_answer_a(resp)
        if answers:
            return answers
        
        # Follow CNAME if present
        cname = extract_cname(resp)
        if cname:
            target = cname.strip(".")
            servers = ROOT_SERVERS[:]  # Restart from root for CNAME
            continue
        
        # Follow NS referral
        ns_names = extract_ns_names(resp)
        if not ns_names:
            return []
        
        # Try to use glue IPs from additional section
        glue = glue_ips_for_ns(resp, ns_names)
        if glue:
            servers = glue
            continue
        
        # No glue: resolve NS hostname to IP
        ns_ip = resolve_nameserver_ip(ns_names[0])
        if ns_ip:
            servers = [ns_ip]
            continue
        
        return []
    
    return []


# HTTP Request to Resolved IP
def http_request(ip: str, host: str) -> Tuple[str, float]:
    """
    Make HTTP request to IP and measure RTT.
    
    Returns: (status_line, rtt_ms)
    """
    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("utf-8")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    
    start = time.perf_counter()
    try:
        s.connect((ip, 80))
        s.sendall(req)
        data = s.recv(4096)
    finally:
        s.close()
    
    rtt_ms = (time.perf_counter() - start) * 1000.0
    
    # Extract HTTP status line
    status_line = ""
    try:
        first_line = data.split(b"\r\n", 1)[0]
        status_line = first_line.decode("utf-8", errors="replace")
    except Exception:
        status_line = "HTTP/1.1 (unable to parse)"
    
    return status_line, rtt_ms


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].strip()
    if not domain:
        print("Error: domain is empty")
        sys.exit(1)
    
    # Perform iterative DNS resolution
    final_ips = iterative_resolve_a(domain, print_steps=True)
    
    if not final_ips:
        print("Failed to resolve domain.")
        sys.exit(2)
    
    resolved_ip = final_ips[0]
    
    # Make HTTP request to resolved IP
    print("--------------------------------------------")
    print(f"Making HTTP request to {resolved_ip}")
    print("--------------------------------------------")
    
    try:
        status, rtt_ms = http_request(resolved_ip, domain)
        print(status)
        print(f"RTT: {int(round(rtt_ms))} ms")
    except (socket.timeout, OSError) as e:
        print(f"HTTP request error: {e}")
        print("RTT: N/A ms")


if __name__ == "__main__":
    main()
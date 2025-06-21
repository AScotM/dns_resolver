import socket
import struct
import sys
import re
import random
from typing import Optional, Tuple

def is_valid_domain(domain: str) -> bool:
    # Accepts most valid domains; does not handle IDNs
    return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$", domain) is not None

class DNSResolver:
    def __init__(self, dns_server: Tuple[str, int] = ("8.8.8.8", 53), timeout: int = 5):
        self.dns_server = dns_server
        self.timeout = timeout

    def _build_query(self, domain: str, query_type: int = 1) -> Tuple[bytes, int]:
        """Builds a DNS query packet and returns it with the transaction ID."""
        tid = random.randint(0, 65535)
        # Header: [ID][Flags][QDCOUNT][ANCOUNT][NSCOUNT][ARCOUNT]
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        # Question
        qname = b""
        for label in domain.split('.'):
            qname += struct.pack("B", len(label)) + label.encode()
        qname += b"\x00"
        question = qname + struct.pack(">HH", query_type, 1)  # QTYPE, QCLASS=IN
        return header + question, tid

    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parses a possibly compressed DNS name."""
        labels = []
        jumped = False
        original_offset = offset
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                # Pointer
                if not jumped:
                    original_offset = offset + 2
                pointer = struct.unpack(">H", data[offset:offset+2])[0] & 0x3FFF
                offset = pointer
                jumped = True
                continue
            else:
                offset += 1
                labels.append(data[offset:offset+length].decode())
                offset += length
        return ".".join(labels), (offset if not jumped else original_offset)

    def _parse_response(self, data: bytes, tid: int, query_type: int) -> Optional[str]:
        """Parses DNS response and returns the first IP address found."""
        if len(data) < 12:
            return None

        # Header
        resp_tid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
        if resp_tid != tid:
            return None  # Transaction ID mismatch
        if (flags >> 15) != 1:  # QR bit must be 1 (response)
            return None
        rcode = flags & 0xF
        if rcode != 0:
            return None  # Non-zero RCODE: error

        # Skip question section
        offset = 12
        for _ in range(qdcount):
            _, offset = self._parse_name(data, offset)
            offset += 4  # QTYPE + QCLASS

        # Parse answer section
        for _ in range(ancount):
            _, offset1 = self._parse_name(data, offset)
            offset = offset1
            if offset + 10 > len(data):
                return None
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            if offset + rdlength > len(data):
                return None
            rdata = data[offset:offset+rdlength]
            offset += rdlength

            if rtype == 1 and rclass == 1 and query_type == 1 and rdlength == 4:
                # A record
                return ".".join(str(b) for b in rdata)
            elif rtype == 28 and rclass == 1 and query_type == 28 and rdlength == 16:
                # AAAA record
                return socket.inet_ntop(socket.AF_INET6, rdata)
        return None

    def resolve(self, domain: str, query_type: str = "A") -> Optional[str]:
        """Resolves a domain to an IP address."""
        if not is_valid_domain(domain):
            raise ValueError("Invalid domain format")
        type_map = {"A": 1, "AAAA": 28}
        qtype = type_map.get(query_type.upper())
        if not qtype:
            raise ValueError("Unsupported query type")

        query, tid = self._build_query(domain, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            try:
                s.sendto(query, self.dns_server)
                data, addr = s.recvfrom(4096)
                # Validate response source
                if addr[0] != self.dns_server[0]:
                    return None
                return self._parse_response(data, tid, qtype)
            except socket.timeout:
                print("DNS request timed out")
                return None
            except socket.error as e:
                print(f"Network error: {e}")
                return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dns_resolver.py <domain> [type=A|AAAA]")
        sys.exit(1)
    resolver = DNSResolver()
    try:
        domain = sys.argv[1]
        query_type = sys.argv[2] if len(sys.argv) > 2 else "A"
        result = resolver.resolve(domain, query_type)
        if result:
            print(f"Resolved {query_type} record for {domain}: {result}")
        else:
            print(f"No {query_type} record found for {domain}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

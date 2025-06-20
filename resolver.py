import socket
import struct
import sys
import re
from typing import Optional, Tuple

class DNSResolver:
    def __init__(self, dns_server: Tuple[str, int] = ("8.8.8.8", 53), timeout: int = 5):
        self.dns_server = dns_server
        self.timeout = timeout

    def _build_query(self, domain: str, query_type: int = 1) -> bytearray:
        """Builds a DNS query packet."""
        msg = bytearray(512)
        
        # Header section
        msg[0:2] = struct.pack(">H", 0x1234)  # Transaction ID
        msg[2:4] = struct.pack(">H", 0x0100)  # Flags (Standard query)
        msg[4:6] = struct.pack(">H", 1)       # Questions
        msg[6:12] = b'\x00' * 6               # Other sections (Answer, Authority, Additional)
        
        # Question section
        offset = 12
        for label in domain.split('.'):
            msg[offset] = len(label)
            offset += 1
            msg[offset:offset + len(label)] = label.encode()
            offset += len(label)
        msg[offset] = 0  # Null terminator
        offset += 1
        
        # Query type (A=1, AAAA=28) and class (IN=1)
        msg[offset:offset+4] = struct.pack(">HH", query_type, 1)
        return msg[:offset + 4]

    def _parse_response(self, data: bytes) -> Optional[str]:
        """Parses DNS response and returns the first IP address found."""
        try:
            # Skip header (12 bytes) and question section
            answer_offset = 12
            while data[answer_offset] != 0:
                answer_offset += 1
            answer_offset += 5  # Skip null byte + QTYPE + QCLASS
            
            # Parse answer section
            while answer_offset < len(data):
                # Handle DNS compression (pointer if first two bits are 11)
                if data[answer_offset] & 0xC0 == 0xC0:
                    answer_offset += 2  # Skip compressed name
                else:
                    while data[answer_offset] != 0:
                        answer_offset += 1
                    answer_offset += 1
                
                # Unpack record metadata
                record_type, record_class, ttl, data_len = struct.unpack(
                    ">HHIH", data[answer_offset:answer_offset+10]
                )
                answer_offset += 10
                
                # Handle different record types
                if record_type == 1 and record_class == 1:  # A record
                    return ".".join(str(b) for b in data[answer_offset:answer_offset+4])
                elif record_type == 28 and record_class == 1:  # AAAA record
                    return ":".join(f"{b:02x}" for b in data[answer_offset:answer_offset+16])
                answer_offset += data_len
        except (struct.error, IndexError):
            return None

    def resolve(self, domain: str, query_type: str = "A") -> Optional[str]:
        """Resolves a domain to an IP address.
        
        Args:
            domain: Domain name to resolve (e.g., "example.com")
            query_type: Query type ("A" for IPv4, "AAAA" for IPv6)
            
        Returns:
            IP address as string or None if resolution failed
        """
        # Validate input
        if not re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", domain.lower()):
            raise ValueError("Invalid domain format")
            
        type_map = {"A": 1, "AAAA": 28}
        query_id = type_map.get(query_type.upper(), 1)
        
        # Build and send query
        query = self._build_query(domain, query_id)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            try:
                s.sendto(query, self.dns_server)
                data, _ = s.recvfrom(512)
                return self._parse_response(data)
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

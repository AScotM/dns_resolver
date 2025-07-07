import socket
import struct
import sys
import re
import random
from typing import Optional, Tuple, List, Union, Dict
import time
import ipaddress

class DNSResolver:
    # Common DNS record types
    RECORD_TYPES = {
        "A": 1,
        "AAAA": 28,
        "MX": 15,
        "CNAME": 5,
        "TXT": 16,
        "NS": 2,
        "SOA": 6,
        "PTR": 12
    }

    def __init__(self, dns_server: Tuple[str, int] = ("8.8.8.8", 53), timeout: int = 5, retries: int = 3):
        self.dns_server = dns_server
        self.timeout = timeout
        self.retries = retries
        self._validate_dns_server()

    def _validate_dns_server(self):
        """Validate the DNS server IP and port"""
        try:
            ipaddress.ip_address(self.dns_server[0])
            if not 0 < self.dns_server[1] <= 65535:
                raise ValueError("Invalid DNS server port number")
        except ValueError as e:
            raise ValueError(f"Invalid DNS server configuration: {e}")

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Improved domain validation with IDN support"""
        if not domain or len(domain) > 253:
            return False
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        # Simplified regex that handles most cases including IDNs (when encoded as punycode)
        label_re = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(label_re.match(label) for label in labels)

    def _build_query(self, domain: str, query_type: int = 1) -> Tuple[bytes, int]:
        """Builds a DNS query packet with improved validation"""
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain name: {domain}")

        tid = random.randint(0, 65535)
        # Header: [ID][Flags][QDCOUNT][ANCOUNT][NSCOUNT][ARCOUNT]
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        
        # Question section with improved encoding
        try:
            qname = b"".join(
                struct.pack("B", len(label)) + label.encode('idna')
                for label in domain.split('.')
            ) + b"\x00"
        except UnicodeError as e:
            raise ValueError(f"Domain encoding error: {e}")

        question = qname + struct.pack(">HH", query_type, 1)  # QTYPE, QCLASS=IN
        return header + question, tid

    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Improved name parsing with better error handling"""
        if offset >= len(data):
            raise ValueError("Invalid offset for DNS name parsing")

        labels = []
        jumped = False
        original_offset = offset
        max_jumps = 10  # Prevent infinite loops with malicious packets
        jump_count = 0

        while True:
            if offset >= len(data):
                raise ValueError("DNS packet parsing overflow")

            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                # Pointer
                if jump_count >= max_jumps:
                    raise ValueError("Too many DNS name pointer jumps")
                jump_count += 1
                
                if not jumped:
                    original_offset = offset + 2
                if offset + 1 >= len(data):
                    raise ValueError("Invalid DNS pointer offset")
                
                pointer = struct.unpack(">H", data[offset:offset+2])[0] & 0x3FFF
                if pointer >= len(data):
                    raise ValueError("DNS pointer out of bounds")
                offset = pointer
                jumped = True
                continue
            else:
                offset += 1
                if offset + length > len(data):
                    raise ValueError("DNS label length exceeds packet size")
                try:
                    labels.append(data[offset:offset+length].decode('idna'))
                except UnicodeError:
                    labels.append(data[offset:offset+length].decode('latin-1'))
                offset += length

        return ".".join(labels), (offset if not jumped else original_offset)

    def _parse_record_data(self, rtype: int, rdata: bytes) -> Union[str, Tuple, Dict]:
        """Parse different DNS record types"""
        if rtype == 1:  # A record
            return ".".join(str(b) for b in rdata)
        elif rtype == 28:  # AAAA record
            return socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 15:  # MX record
            preference = struct.unpack(">H", rdata[:2])[0]
            exchange, _ = self._parse_name(rdata, 2)
            return (preference, exchange)
        elif rtype == 5:  # CNAME
            return self._parse_name(rdata, 0)[0]
        elif rtype == 16:  # TXT
            return rdata[1:].decode('utf-8', errors='replace')  # Skip length byte
        else:
            return rdata.hex()  # Return hex for unsupported types

    def _parse_response(self, data: bytes, tid: int, query_type: int) -> List[Dict]:
        """Enhanced response parsing that returns all records with metadata"""
        if len(data) < 12:
            raise ValueError("DNS response too short")

        # Header
        resp_tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        if resp_tid != tid:
            raise ValueError("Transaction ID mismatch")
        if (flags >> 15) != 1:
            raise ValueError("Not a DNS response")
        
        rcode = flags & 0xF
        if rcode != 0:
            error_codes = {0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain"}
            raise ValueError(f"DNS error: {error_codes.get(rcode, f'Unknown({rcode})')}")

        results = []
        offset = 12

        # Skip question section
        for _ in range(qdcount):
            try:
                _, offset = self._parse_name(data, offset)
                offset += 4  # QTYPE + QCLASS
            except ValueError as e:
                raise ValueError(f"Error parsing question section: {e}")

        # Parse answer section
        for section, count in [("answer", ancount), ("authority", nscount), ("additional", arcount)]:
            for _ in range(count):
                try:
                    name, offset1 = self._parse_name(data, offset)
                    offset = offset1
                    if offset + 10 > len(data):
                        raise ValueError("Record header exceeds packet size")

                    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
                    offset += 10
                    if offset + rdlength > len(data):
                        raise ValueError("Record data exceeds packet size")

                    rdata = data[offset:offset+rdlength]
                    offset += rdlength

                    if rclass == 1:  # IN class
                        try:
                            parsed_data = self._parse_record_data(rtype, rdata)
                            results.append({
                                "name": name,
                                "type": rtype,
                                "type_str": next((k for k, v in self.RECORD_TYPES.items() if v == rtype), str(rtype)),
                                "class": rclass,
                                "ttl": ttl,
                                "data": parsed_data,
                                "section": section
                            })
                        except ValueError as e:
                            continue  # Skip records we can't parse
                except ValueError as e:
                    continue  # Skip malformed records

        return results

    def resolve(self, domain: str, query_type: str = "A") -> List[Dict]:
        """
        Resolves DNS records with retries and improved error handling.
        
        Returns:
            List of dictionaries containing record information
        """
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")

        qtype = self.RECORD_TYPES.get(query_type.upper())
        if not qtype:
            raise ValueError(f"Unsupported query type: {query_type}")

        query, tid = self._build_query(domain, qtype)
        last_error = None

        for attempt in range(self.retries):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                try:
                    start_time = time.time()
                    s.sendto(query, self.dns_server)
                    data, addr = s.recvfrom(4096)
                    
                    # Validate response source
                    if addr[0] != self.dns_server[0] or addr[1] != self.dns_server[1]:
                        raise ValueError("Response from unexpected server")

                    results = self._parse_response(data, tid, qtype)
                    if results:
                        return results
                    else:
                        raise ValueError("No matching records found")

                except socket.timeout:
                    last_error = f"Attempt {attempt + 1}: DNS request timed out"
                except (socket.error, ValueError) as e:
                    last_error = f"Attempt {attempt + 1}: {str(e)}"
                except Exception as e:
                    last_error = f"Attempt {attempt + 1}: Unexpected error - {str(e)}"

        raise Exception(f"All attempts failed. Last error: {last_error}")

    def query(self, domain: str, query_type: str = "A") -> None:
        """User-friendly query method that prints results"""
        try:
            records = self.resolve(domain, query_type)
            print(f"\nDNS {query_type} records for {domain}:")
            for rec in records:
                print(f"{rec['type_str']} {rec['name']} {rec['ttl']} {rec['data']}")
        except Exception as e:
            print(f"Error resolving {domain}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dns_resolver.py <domain> [type=A|AAAA|MX|...]")
        sys.exit(1)

    resolver = DNSResolver()
    try:
        domain = sys.argv[1]
        query_type = sys.argv[2] if len(sys.argv) > 2 else "A"
        resolver.query(domain, query_type)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

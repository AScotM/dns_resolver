import socket
import struct
import sys
import re
import random
import time
import ipaddress
from typing import Optional, Tuple, List, Union, Dict, Any
from dataclasses import dataclass
import logging
from enum import IntEnum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class DNSRecordType(IntEnum):
    """DNS record types from IANA registry"""
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    DNAME = 39
    HTTPS = 65

@dataclass
class DNSRecord:
    """Dataclass for DNS record representation"""
    name: str
    type: DNSRecordType
    ttl: int
    data: Any
    section: str = "answer"
    preference: Optional[int] = None  # For MX records

    def __str__(self):
        type_str = self.type.name
        if self.type == DNSRecordType.MX:
            return f"{type_str}\t{self.preference}\t{self.data}"
        return f"{type_str}\t{self.data}"

class DNSResolver:
    DEFAULT_DNS_SERVERS = [
        ("8.8.8.8", 53),    # Google DNS
        ("1.1.1.1", 53),    # Cloudflare DNS
        ("9.9.9.9", 53),    # Quad9 DNS
        ("208.67.222.222", 53)  # OpenDNS
    ]

    def __init__(
        self,
        dns_servers: List[Tuple[str, int]] = None,
        timeout: int = 5,
        retries: int = 3,
        use_tcp: bool = False
    ):
        self.dns_servers = dns_servers or self.DEFAULT_DNS_SERVERS
        self.timeout = timeout
        self.retries = retries
        self.use_tcp = use_tcp
        self._validate_dns_servers()

    def _validate_dns_servers(self):
        """Validate all DNS server configurations"""
        for server in self.dns_servers:
            try:
                ipaddress.ip_address(server[0])
                if not 0 < server[1] <= 65535:
                    raise ValueError(f"Invalid port number for DNS server {server}")
            except ValueError as e:
                raise ValueError(f"Invalid DNS server configuration {server}: {e}")

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Improved domain validation with IDN support and length checks"""
        if not domain or len(domain) > 253:
            return False
        
        # Check each label
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        
        label_re = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(label_re.match(label) for label in labels)

    def _build_query(self, domain: str, query_type: DNSRecordType) -> Tuple[bytes, int]:
        """Builds a DNS query packet with EDNS support"""
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain name: {domain}")

        tid = random.randint(0, 65535)
        # Header: [ID][Flags][QDCOUNT][ANCOUNT][NSCOUNT][ARCOUNT]
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 1)  # Set ARCOUNT=1 for EDNS
        
        # Question section
        try:
            qname = b"".join(
                struct.pack("B", len(label)) + label.encode('idna')
                for label in domain.split('.')
            ) + b"\x00"
        except UnicodeError as e:
            raise ValueError(f"Domain encoding error: {e}")

        question = qname + struct.pack(">HH", int(query_type), 1)  # QTYPE, QCLASS=IN
        
        # EDNS pseudo-record (OPT record)
        edns = struct.pack(">BBHHIH", 0, 0x29, 0x1000, 0, 0, 0)  # EDNS version 0, payload 4096
        
        return header + question + edns, tid

    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parses DNS names with compression and validation"""
        if offset >= len(data):
            raise ValueError("Offset beyond packet length")

        labels = []
        jumped = False
        original_offset = offset
        max_jumps = 10
        jump_count = 0

        while True:
            if offset >= len(data):
                raise ValueError("DNS packet parsing overflow")

            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                # Pointer compression
                if jump_count >= max_jumps:
                    raise ValueError("Too many DNS pointer jumps")
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

    def _parse_record_data(self, rtype: DNSRecordType, rdata: bytes) -> Any:
        """Parse DNS record data based on type"""
        try:
            if rtype == DNSRecordType.A:
                return socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == DNSRecordType.AAAA:
                return socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == DNSRecordType.MX:
                preference = struct.unpack(">H", rdata[:2])[0]
                exchange, _ = self._parse_name(rdata, 2)
                return exchange, preference
            elif rtype == DNSRecordType.CNAME:
                return self._parse_name(rdata, 0)[0]
            elif rtype == DNSRecordType.TXT:
                return rdata[1:].decode('utf-8', errors='replace')
            elif rtype == DNSRecordType.NS:
                return self._parse_name(rdata, 0)[0]
            elif rtype == DNSRecordType.SOA:
                mname, offset = self._parse_name(rdata, 0)
                rname, offset = self._parse_name(rdata, offset)
                items = struct.unpack(">IIIII", rdata[offset:offset+20])
                return {
                    "mname": mname,
                    "rname": rname,
                    "serial": items[0],
                    "refresh": items[1],
                    "retry": items[2],
                    "expire": items[3],
                    "minimum": items[4]
                }
            else:
                return rdata.hex()
        except Exception as e:
            logger.warning(f"Failed to parse record type {rtype}: {e}")
            return rdata.hex()

    def _parse_response(self, data: bytes, tid: int) -> List[DNSRecord]:
        """Parse DNS response into structured records"""
        if len(data) < 12:
            raise ValueError("DNS response too short")

        # Parse header
        resp_tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        if resp_tid != tid:
            raise ValueError("Transaction ID mismatch")
        if (flags >> 15) != 1:
            raise ValueError("Not a DNS response")
        
        rcode = flags & 0xF
        if rcode != 0:
            error_codes = {
                0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
                8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"
            }
            raise ValueError(f"DNS error: {error_codes.get(rcode, f'RCODE_{rcode}')}")

        records = []
        offset = 12

        # Skip question section
        for _ in range(qdcount):
            _, offset = self._parse_name(data, offset)
            offset += 4  # QTYPE + QCLASS

        # Parse answer, authority, and additional sections
        sections = [
            ("answer", ancount),
            ("authority", nscount),
            ("additional", arcount)
        ]

        for section, count in sections:
            for _ in range(count):
                try:
                    name, offset = self._parse_name(data, offset)
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
                            record_type = DNSRecordType(rtype)
                            parsed_data = self._parse_record_data(record_type, rdata)
                            
                            if record_type == DNSRecordType.MX:
                                exchange, preference = parsed_data
                                record = DNSRecord(
                                    name=name,
                                    type=record_type,
                                    ttl=ttl,
                                    data=exchange,
                                    section=section,
                                    preference=preference
                                )
                            else:
                                record = DNSRecord(
                                    name=name,
                                    type=record_type,
                                    ttl=ttl,
                                    data=parsed_data,
                                    section=section
                                )
                            records.append(record)
                        except (ValueError, Exception) as e:
                            logger.debug(f"Skipping record due to parse error: {e}")
                            continue
                except ValueError as e:
                    logger.warning(f"Error parsing record: {e}")
                    continue

        return records

    def _send_query(self, query: bytes, server: Tuple[str, int]) -> bytes:
        """Send DNS query using UDP or TCP"""
        if self.use_tcp:
            # TCP requires 2-byte length prefix
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(server)
                s.send(struct.pack(">H", len(query)) + query)
                response_length = struct.unpack(">H", s.recv(2))[0]
                return s.recv(response_length)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(query, server)
                return s.recv(4096)

    def resolve(
        self,
        domain: str,
        query_type: Union[str, DNSRecordType] = DNSRecordType.A,
        server: Optional[Tuple[str, int]] = None
    ) -> List[DNSRecord]:
        """
        Resolve DNS records with retries and fallback servers.
        
        Args:
            domain: Domain name to query
            query_type: DNS record type as string or DNSRecordType enum
            server: Specific DNS server to use (optional)
            
        Returns:
            List of DNSRecord objects
        """
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")

        try:
            if isinstance(query_type, str):
                query_type = DNSRecordType[query_type.upper()]
        except KeyError:
            raise ValueError(f"Unsupported query type: {query_type}")

        servers = [server] if server else self.dns_servers
        last_error = None

        for attempt in range(self.retries):
            for current_server in servers:
                try:
                    query, tid = self._build_query(domain, query_type)
                    start_time = time.time()
                    
                    data = self._send_query(query, current_server)
                    if not data:
                        raise ValueError("Empty response from DNS server")

                    # Validate response source (for UDP only)
                    if not self.use_tcp:
                        if len(data) < 12:
                            raise ValueError("Truncated DNS response")
                        resp_tid = struct.unpack(">H", data[:2])[0]
                        if resp_tid != tid:
                            raise ValueError("Transaction ID mismatch")

                    records = self._parse_response(data, tid)
                    if not records:
                        raise ValueError("No records found in response")

                    # Filter for requested type (unless it was ANY)
                    if query_type != DNSRecordType.A:
                        records = [r for r in records if r.type == query_type]
                    
                    if records:
                        logger.info(
                            f"Resolved {domain} ({query_type.name}) via {current_server[0]} "
                            f"in {(time.time()-start_time)*1000:.2f}ms"
                        )
                        return records

                except (socket.timeout, socket.error) as e:
                    last_error = f"Network error with {current_server[0]}: {e}"
                    logger.warning(last_error)
                except ValueError as e:
                    last_error = f"Protocol error with {current_server[0]}: {e}"
                    logger.warning(last_error)
                except Exception as e:
                    last_error = f"Unexpected error with {current_server[0]}: {e}"
                    logger.error(last_error, exc_info=True)

        raise Exception(f"All attempts failed. Last error: {last_error}")

    def query(
        self,
        domain: str,
        query_type: Union[str, DNSRecordType] = "A",
        verbose: bool = False
    ) -> None:
        """User-friendly DNS query interface"""
        try:
            records = self.resolve(domain, query_type)
            print(f"\nDNS {query_type} records for {domain}:")
            
            for section in ["answer", "authority", "additional"]:
                section_records = [r for r in records if r.section == section]
                if section_records:
                    print(f"\n;; {section.capitalize()} Section:")
                    for rec in section_records:
                        if verbose:
                            print(f"{rec.name}\t{rec.ttl}\t{rec}")
                        else:
                            print(rec)
            
            print()  # Add final newline
        except Exception as e:
            print(f"\nError resolving {domain}: {e}\n", file=sys.stderr)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DNS Resolver")
    parser.add_argument("domain", help="Domain name to query")
    parser.add_argument(
        "-t", "--type",
        default="A",
        help="DNS record type (A, AAAA, MX, etc.)"
    )
    parser.add_argument(
        "-s", "--server",
        help="Specific DNS server (ip:port)"
    )
    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Use TCP instead of UDP"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        server = None
        if args.server:
            parts = args.server.split(":")
            ip = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 53
            server = (ip, port)

        resolver = DNSResolver(use_tcp=args.tcp)
        resolver.query(
            args.domain,
            query_type=args.type,
            verbose=args.verbose
        )
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

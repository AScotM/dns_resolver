import socket
import struct
import sys
import re
import random
import time
import ipaddress
from typing import Optional, Tuple, List, Union, Dict, Any, Set
from dataclasses import dataclass
import logging
from enum import IntEnum
import json
from collections import defaultdict

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
    DS = 43
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    HTTPS = 65
    ANY = 255  # Special case for ANY queries

@dataclass
class DNSRecord:
    """Dataclass for DNS record representation"""
    name: str
    type: DNSRecordType
    ttl: int
    data: Any
    section: str = "answer"
    preference: Optional[int] = None  # For MX records
    rdata: Optional[bytes] = None  # Original raw data

    def __str__(self):
        type_str = self.type.name
        if self.type == DNSRecordType.MX:
            return f"{type_str}\t{self.preference}\t{self.data}"
        elif self.type == DNSRecordType.SOA:
            soa = self.data
            return (f"{type_str}\t{soa['mname']} {soa['rname']} "
                    f"({soa['serial']} {soa['refresh']} {soa['retry']} "
                    f"{soa['expire']} {soa['minimum']})")
        elif self.type == DNSRecordType.TXT:
            return f"{type_str}\t\"{self.data}\""
        return f"{type_str}\t{self.data}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for JSON serialization"""
        result = {
            "name": self.name,
            "type": self.type.name,
            "ttl": self.ttl,
            "section": self.section
        }
        if self.type == DNSRecordType.MX:
            result["preference"] = self.preference
            result["exchange"] = self.data
        elif self.type == DNSRecordType.SOA:
            result.update(self.data)
        else:
            result["data"] = self.data
        return result

class DNSResolver:
    DEFAULT_DNS_SERVERS = [
        ("8.8.8.8", 53),    # Google DNS
        ("1.1.1.1", 53),    # Cloudflare DNS
        ("9.9.9.9", 53),    # Quad9 DNS
        ("208.67.222.222", 53)  # OpenDNS
    ]
    MAX_UDP_SIZE = 4096
    MAX_CNAME_REDIRECTS = 15
    DEFAULT_TIMEOUT = 5
    DEFAULT_RETRIES = 3

    def __init__(
        self,
        dns_servers: List[Tuple[str, int]] = None,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        use_tcp: bool = False,
        validate_dnssec: bool = False
    ):
        self.dns_servers = dns_servers or self.DEFAULT_DNS_SERVERS
        self.timeout = timeout
        self.retries = retries
        self.use_tcp = use_tcp
        self.validate_dnssec = validate_dnssec  # Note: sets DO bit only; no full validation here
        self._validate_dns_servers()
        self._query_stats = defaultdict(int)
        self._socket_pool: Dict[Tuple[str, int], socket.socket] = {}  # For TCP connection pooling

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
        """
        Permissive domain validation:
        - total length <= 253
        - at least two labels
        - allow underscores (used in SRV, DKIM, etc.)
        - labels 1..63 chars, no leading/trailing hyphen
        """
        if not domain or len(domain) > 253:
            return False
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        label_re = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
        return all(label_re.match(label) for label in labels)

    def _build_query(
        self,
        domain: str,
        query_type: DNSRecordType,
        dnssec: bool = False
    ) -> Tuple[bytes, int]:
        """Builds a DNS query packet with EDNS support"""
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain name: {domain}")

        tid = random.randint(0, 65535)
        flags = 0x0100  # Standard query with recursion desired

        # Header: [ID][Flags][QDCOUNT][ANCOUNT][NSCOUNT][ARCOUNT]
        header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 1)  # ARCOUNT=1 for EDNS

        # Question
        try:
            qname = b"".join(
                struct.pack("B", len(label)) + label.encode('idna')
                for label in domain.split('.')
            ) + b"\x00"
        except UnicodeError as e:
            raise ValueError(f"Domain encoding error: {e}")

        question = qname + struct.pack(">HH", int(query_type), 1)  # QTYPE, QCLASS=IN

        # EDNS(0) OPT record
        udp_payload = 4096
        edns_flags = 0x80000000 if dnssec else 0  # DO bit
        edns = b'\x00' + struct.pack(">HHIH", 41, udp_payload, edns_flags, 0)

        return header + question + edns, tid

    def _parse_name(
        self,
        data: bytes,
        offset: int,
        seen_pointers: Optional[Set[int]] = None
    ) -> Tuple[str, int]:
        """Parses DNS names with compression and loop detection"""
        if offset >= len(data):
            raise ValueError("Offset beyond packet length")

        if seen_pointers is None:
            seen_pointers = set()

        labels = []
        jumped = False
        original_offset = offset
        max_jumps = 20
        jump_count = 0

        while True:
            if offset in seen_pointers:
                raise ValueError("DNS compression loop detected")
            seen_pointers.add(offset)

            if offset >= len(data):
                raise ValueError("DNS packet parsing overflow")

            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                # Pointer compression
                if offset + 1 >= len(data):
                    raise ValueError("Invalid DNS pointer offset")
                pointer = struct.unpack(">H", data[offset:offset+2])[0] & 0x3FFF
                if pointer >= len(data):
                    raise ValueError("DNS pointer out of bounds")
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumped = True
                jump_count += 1
                if jump_count > max_jumps:
                    raise ValueError("Too many DNS pointer jumps")
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

    def _parse_record_data(
        self,
        rtype: DNSRecordType,
        rdata: bytes,
        packet: bytes,
        rdata_start: int
    ) -> Any:
        """Parse DNS record data based on type"""
        try:
            if rtype == DNSRecordType.A:
                if len(rdata) != 4:
                    raise ValueError("Invalid A record length")
                return socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == DNSRecordType.AAAA:
                if len(rdata) != 16:
                    raise ValueError("Invalid AAAA record length")
                return socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == DNSRecordType.MX:
                if len(rdata) < 3:
                    raise ValueError("MX record too short")
                preference = struct.unpack(">H", rdata[:2])[0]
                exchange, _ = self._parse_name(packet, rdata_start + 2)
                return exchange, preference
            elif rtype in (DNSRecordType.CNAME, DNSRecordType.NS, DNSRecordType.PTR, DNSRecordType.DNAME):
                return self._parse_name(packet, rdata_start)[0]
            elif rtype == DNSRecordType.TXT:
                parts = []
                pos = 0
                while pos < len(rdata):
                    if pos + 1 > len(rdata):
                        break
                    txt_len = rdata[pos]
                    pos += 1
                    if pos + txt_len > len(rdata):
                        break
                    parts.append(rdata[pos:pos + txt_len].decode('utf-8', errors='replace'))
                    pos += txt_len
                return ''.join(parts)
            elif rtype == DNSRecordType.SOA:
                offset = rdata_start
                mname, offset = self._parse_name(packet, offset)
                rname, offset = self._parse_name(packet, offset)
                if offset + 20 > len(packet):
                    raise ValueError("SOA numeric fields truncated")
                items = struct.unpack(">IIIII", packet[offset:offset+20])
                return {
                    "mname": mname,
                    "rname": rname,
                    "serial": items[0],
                    "refresh": items[1],
                    "retry": items[2],
                    "expire": items[3],
                    "minimum": items[4]
                }
            elif rtype == DNSRecordType.DS:
                if len(rdata) < 4:
                    raise ValueError("DS record too short")
                key_tag, algorithm, digest_type = struct.unpack(">HBB", rdata[:4])
                digest = rdata[4:].hex()
                return {"key_tag": key_tag, "algorithm": algorithm, "digest_type": digest_type, "digest": digest}
            elif rtype == DNSRecordType.DNSKEY:
                if len(rdata) < 4:
                    raise ValueError("DNSKEY record too short")
                flags, protocol, algorithm = struct.unpack(">HBB", rdata[:4])
                key = rdata[4:].hex()
                return {"flags": flags, "protocol": protocol, "algorithm": algorithm, "key": key}
            else:
                return rdata.hex()
        except Exception as e:
            logger.warning(f"Failed to parse record type {rtype}: {e}")
            return rdata.hex()

    def _parse_response(self, data: bytes, tid: int) -> List[DNSRecord]:
        """Parse DNS response into structured records"""
        if len(data) < 12:
            raise ValueError("DNS response too short")

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

        # Warn on truncation (TC)
        truncated = (flags >> 9) & 0x1
        if truncated and not self.use_tcp:
            logger.warning("Response truncated (TC=1), consider using TCP")

        records: List[DNSRecord] = []
        offset = 12

        # Skip questions
        for _ in range(qdcount):
            _, offset = self._parse_name(data, offset)
            if offset + 4 > len(data):
                raise ValueError("Question section truncated")
            offset += 4  # QTYPE + QCLASS

        # Sections
        for section, count in (("answer", ancount), ("authority", nscount), ("additional", arcount)):
            for _ in range(count):
                name, offset = self._parse_name(data, offset)
                if offset + 10 > len(data):
                    raise ValueError("RR header exceeds packet size")
                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
                offset += 10
                if offset + rdlength > len(data):
                    raise ValueError("RR data exceeds packet size")
                rdata = data[offset:offset+rdlength]
                rdata_start = offset
                offset += rdlength

                if rclass != 1:  # only IN
                    continue
                try:
                    record_type = DNSRecordType(rtype)
                except ValueError:
                    # Unknown type -> keep raw
                    parsed = rdata.hex()
                    records.append(DNSRecord(name=name, type=DNSRecordType.ANY, ttl=ttl, data=parsed, section=section, rdata=rdata))
                    continue

                parsed_data = self._parse_record_data(record_type, rdata, data, rdata_start)
                if record_type == DNSRecordType.MX and isinstance(parsed_data, tuple):
                    exchange, preference = parsed_data
                    records.append(DNSRecord(name=name, type=record_type, ttl=ttl, data=exchange,
                                             section=section, preference=preference, rdata=rdata))
                else:
                    records.append(DNSRecord(name=name, type=record_type, ttl=ttl, data=parsed_data,
                                             section=section, rdata=rdata))
        return records

    def _get_tcp_socket(self, server: Tuple[str, int]) -> socket.socket:
        """Get a TCP socket from pool or create new one"""
        sock = self._socket_pool.get(server)
        if sock:
            try:
                sock.send(b'')  # may raise if closed
                return sock
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                self._socket_pool.pop(server, None)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(server)
        self._socket_pool[server] = sock
        return sock

    def _recv_all(self, sock: socket.socket, n: int) -> bytes:
        """Receive exactly n bytes from TCP socket"""
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise socket.error("Socket closed before receiving full response")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _send_query(self, query: bytes, server: Tuple[str, int]) -> bytes:
        """Send DNS query using UDP or TCP and return raw response"""
        if self.use_tcp:
            sock = self._get_tcp_socket(server)
            try:
                sock.send(struct.pack(">H", len(query)) + query)
                hdr = self._recv_all(sock, 2)
                response_length = struct.unpack(">H", hdr)[0]
                return self._recv_all(sock, response_length)
            except socket.error:
                # Remove broken socket from pool
                self._socket_pool.pop(server, None)
                raise
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(query, server)
                data, addr = s.recvfrom(self.MAX_UDP_SIZE)
                # Verify source matches server (helps avoid stray packets)
                if addr[0] != server[0]:
                    raise ValueError(f"Response from unexpected source {addr[0]} (expected {server[0]})")
                return data

    def _follow_cname_chain_query(
        self,
        cname_target: str,
        qtype: DNSRecordType,
        server: Tuple[str, int],
        attempts_left: int
    ) -> List[DNSRecord]:
        """Resolve the CNAME target recursively (bounded)."""
        if attempts_left <= 0:
            logger.warning("CNAME redirect limit reached")
            return []
        # Perform a child resolve with same server to reduce variance; keep same transport
        child = DNSResolver(
            dns_servers=[server],
            timeout=self.timeout,
            retries=self.retries,
            use_tcp=self.use_tcp,
            validate_dnssec=self.validate_dnssec
        )
        try:
            return child.resolve(cname_target, qtype, server=server, follow_cnames=True)
        finally:
            child.close()

    def resolve(
        self,
        domain: str,
        query_type: Union[str, DNSRecordType, List[Union[str, DNSRecordType]]] = DNSRecordType.A,
        server: Optional[Tuple[str, int]] = None,
        follow_cnames: bool = True
    ) -> List[DNSRecord]:
        """
        Resolve DNS records with retries and fallback servers.

        Args:
            domain: Domain name to query
            query_type: DNS record type(s) as string, enum, or list of types
            server: Specific DNS server to use (optional)
            follow_cnames: If True, follow CNAME chains when needed

        Returns:
            List of DNSRecord objects
        """
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")

        # Multiple query types: aggregate results
        if isinstance(query_type, (list, tuple)):
            results: List[DNSRecord] = []
            for qt in query_type:
                try:
                    results.extend(self.resolve(domain, qt, server, follow_cnames))
                except Exception as e:
                    logger.warning(f"Failed to resolve {qt} for {domain}: {e}")
            return results

        # Convert string to enum if needed
        if isinstance(query_type, str):
            try:
                query_type = DNSRecordType[query_type.upper()]
            except KeyError:
                raise ValueError(f"Unsupported query type: {query_type}")

        servers = [server] if server else self.dns_servers
        last_error = None

        for attempt in range(self.retries):
            for current_server in servers:
                try:
                    self._query_stats[current_server] += 1
                    query, tid = self._build_query(domain, query_type, self.validate_dnssec)
                    start_time = time.time()

                    data = self._send_query(query, current_server)
                    if not data:
                        raise ValueError("Empty response from DNS server")

                    # For UDP, _parse_response already re-checks TID; ok to parse directly
                    records = self._parse_response(data, tid)
                    if not records:
                        raise ValueError("No records in response")

                    # Keep CNAMEs to decide about following; only final filtering after.
                    final_records = records

                    # If not ANY and not the requested type, and CNAME exists in answer, follow it
                    if query_type != DNSRecordType.ANY:
                        wanted = [r for r in records if r.type == query_type and r.section == "answer"]
                        if wanted:
                            final_records = wanted
                        elif follow_cnames:
                            cnames = [r for r in records if r.type == DNSRecordType.CNAME and r.section == "answer"]
                            if cnames:
                                # Follow first CNAME (common case). Could follow chain, but next resolve handles.
                                cname_target = cnames[0].data
                                logger.debug(f"Following CNAME {domain} -> {cname_target}")
                                final_records = self._follow_cname_chain_query(
                                    cname_target, query_type, current_server, self.MAX_CNAME_REDIRECTS
                                )

                    if query_type == DNSRecordType.ANY:
                        final_records = records  # return everything

                    if final_records:
                        logger.info(
                            f"Resolved {domain} ({query_type.name}) via {current_server[0]} "
                            f"in {(time.time()-start_time)*1000:.2f}ms"
                        )
                        return final_records

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
        query_type: Union[str, DNSRecordType, List[Union[str, DNSRecordType]]] = "A",
        server: Optional[Tuple[str, int]] = None,
        verbose: bool = False,
        json_output: bool = False,
        follow_cnames: bool = True
    ) -> None:
        """User-friendly DNS query interface"""
        try:
            records = self.resolve(domain, query_type, server, follow_cnames)

            if json_output:
                if isinstance(query_type, list):
                    qtype_str = [qt if isinstance(qt, str) else qt.name for qt in query_type]
                else:
                    qtype_str = query_type if isinstance(query_type, str) else query_type.name
                result = {
                    "domain": domain,
                    "query_type": qtype_str,
                    "records": [r.to_dict() for r in records]
                }
                print(json.dumps(result, indent=2))
                return

            if isinstance(query_type, list):
                type_str = ",".join(t if isinstance(t, str) else t.name for t in query_type)
            else:
                type_str = query_type if isinstance(query_type, str) else query_type.name

            print(f"\nDNS {type_str} records for {domain}:")
            # If we got mixed sections (from ANY or recursion), group them for output
            sections = defaultdict(list)
            for r in records:
                sections[r.section].append(r)
            for sec_name in ["answer", "authority", "additional"]:
                if sections[sec_name]:
                    print(f"\n;; {sec_name.capitalize()} Section:")
                    for rec in sections[sec_name]:
                        if verbose:
                            print(f"{rec.name}\t{rec.ttl}\t{rec}")
                        else:
                            print(rec)
            print()
        except Exception as e:
            print(f"\nError resolving {domain}: {e}\n", file=sys.stderr)

    def get_stats(self) -> Dict[Tuple[str, int], int]:
        """Get query statistics per server"""
        return dict(self._query_stats)

    def close(self):
        """Clean up resources"""
        for sock in list(self._socket_pool.values()):
            try:
                sock.close()
            except Exception:
                pass
        self._socket_pool.clear()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DNS Resolver")
    parser.add_argument("domain", help="Domain name to query")
    parser.add_argument(
        "-t", "--type",
        default="A",
        help="DNS record type (A, AAAA, MX, etc.) or comma-separated list"
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
        "--dnssec",
        action="store_true",
        help="Set DO bit (request DNSSEC records)"
    )
    parser.add_argument(
        "--no-follow-cnames",
        action="store_true",
        help="Disable following CNAME records"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
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

        query_types = args.type.split(",") if "," in args.type else args.type

        resolver = DNSResolver(
            use_tcp=args.tcp,
            validate_dnssec=args.dnssec
        )
        try:
            resolver.query(
                args.domain,
                query_type=query_types,
                server=server,
                verbose=args.verbose,
                json_output=args.json,
                follow_cnames=not args.no_follow_cnames
            )
        finally:
            resolver.close()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

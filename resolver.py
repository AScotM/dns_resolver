import socket
import struct
import sys


def resolve_dns(domain):
    # Google's public DNS server
    server = ("8.8.8.8", 53)

    # Build the DNS request message
    msg = bytearray(512)
    msg[0:2] = struct.pack(">H", 0x1234)  # Random transaction ID
    msg[2:4] = struct.pack(">H", 0x0100)  # Flags (standard query)
    msg[4:6] = struct.pack(">H", 1)       # Number of questions
    msg[6:8] = struct.pack(">H", 0)       # Number of answer RRs
    msg[8:10] = struct.pack(">H", 0)      # Number of authority RRs
    msg[10:12] = struct.pack(">H", 0)     # Number of additional RRs

    # Add the domain name to the question section
    labels = domain.split(".")
    offset = 12  # Start after the header
    for label in labels:
        msg[offset] = len(label)  # Length of label
        offset += 1
        msg[offset:offset + len(label)] = label.encode()  # Label itself
        offset += len(label)
    msg[offset] = 0  # Null byte at the end of the domain
    offset += 1

    # Type A (IPv4 address) and Class IN (Internet)
    msg[offset:offset + 4] = struct.pack(">HH", 1, 1)
    offset += 4

    # Send the DNS query via UDP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(msg[:offset], server)
        data, _ = s.recvfrom(512)

    # Now parse the DNS response
    response_header = data[:12]  # First 12 bytes are the header, we can skip them
    answer_offset = 12  # Start after the header

    # Skip the question section (domain name + type + class)
    while data[answer_offset] != 0:
        answer_offset += 1
    answer_offset += 5  # Skip the null byte + type + class fields

    # Now answer_offset points to the answer section, skip the name pointer
    answer_offset += 2  # Skip the name pointer

    # Unpack the answer section (type, class, ttl, data length)
    try:
        record_type, record_class, record_ttl, data_len = struct.unpack(">HHIH", data[answer_offset:answer_offset + 10])
        answer_offset += 10
    except struct.error:
        print("Error unpacking DNS response.")
        return

    # Check if the record type is A (0x01) for IPv4 address
    if record_type == 1:  # Type A (IPv4 address)
        ip = ".".join(str(b) for b in data[answer_offset:answer_offset + 4])
        print(f"Resolved IP: {ip}")
    else:
        print("No A record found in response.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python resolve_dns.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    resolve_dns(domain)

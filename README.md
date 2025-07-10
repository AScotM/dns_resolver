USAGE:
python resolver.py example.com [options]

Options:
  -t, --type <TYPE>      Record type (A, MX, etc.) or comma-separated list
  -s, --server <IP:PORT> Use specific DNS server
  --tcp                  Use TCP instead of UDP
  --dnssec               Enable DNSSEC validation
  --no-follow-cnames     Disable CNAME following
  -v, --verbose          Detailed output
  --json                 JSON format output
  --debug                Enable debug logging

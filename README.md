Usage examples: 
# Basic A record lookup
python resolver.py example.com

# MX records with DNSSEC
python resolver.py example.com -t MX --dnssec

# Multiple record types in JSON
python resolver.py example.com -t A,AAAA,MX --json

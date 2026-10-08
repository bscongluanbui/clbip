import ipaddress

lines = [
    "inet6 2001:db8::1/64 scope global",
    "inet6 2001:db8::2 scope global",
    "inet6 fe80::1/64 scope link",
    "inet6 2405:4802::1234/64 valid_lft 2592000sec preferred_lft 604800sec scope global",
    "inet6 2a01:4f8:xxxx::1/128 scope global dynamic mngtmpaddr",
    "inet6 fd00::1/64 scope global",
    "inet6 2001:db8::1%eth0/64 scope global"
]

for line in lines:
    parts = line.split()
    if len(parts) >= 2:
        addr_with_prefix = parts[1]
        scope = ''
        if 'scope' in parts:
            scope_idx = parts.index('scope') + 1
            if scope_idx < len(parts):
                scope = parts[scope_idx]
        
        print(f"Address: {addr_with_prefix}, Scope: {scope}")
        
        if scope == 'global':
            try:
                addr_str, prefix_len = addr_with_prefix.split('/')
                # mock stripping the zone index just in case
                # addr_str = addr_str.split('%')[0]
                prefix_len = int(prefix_len)
                network = ipaddress.IPv6Network(f"{addr_str}/{prefix_len}", strict=False)
                print(f"  -> Valid subnet: {network.network_address}/{prefix_len}")
            except Exception as e:
                print(f"  -> Exception: {e}")


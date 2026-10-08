"""Read-only IPv6 inspection. Importing this module has no NIC side effects."""
import argparse
import json


def main():
    from ipv6_manager import get_ipv6_addresses, validate_interface
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    args = parser.parse_args()
    print(json.dumps(get_ipv6_addresses(validate_interface(args.interface), strict=True), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

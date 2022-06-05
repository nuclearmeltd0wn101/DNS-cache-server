import argparse
import socket
import sys

from resolver import DNSResolver

MIN_PORT = 1
MAX_PORT = 65535

def main():
    parser = argparse.ArgumentParser(
        description="Caching & resolving last mile DNS server")
    parser.add_argument('-P', type=int, help='server port (default: 53)', default=53)
    parser.add_argument('-i', type=str, help='DNS forwarder IP (required)')
    parser.add_argument('-p', type=int, help='DNS forwarder port (default: 53)', default=53)

    args = parser.parse_args()
    if not args.i:
        print('Insufficient arguments provided. Use --help')
        sys.exit(0)

    port = args.P
    forwarder_ip = args.i
    forwarder_port = args.p
    try:
        forwarder = (socket.gethostbyname(forwarder_ip), forwarder_port)
    except socket.gaierror:
        print("Unable to resolve forwarder IP or invalid one is submitted")
        sys.exit()

    try:
        port = int(port)
        if port < MIN_PORT or port > MAX_PORT:
            print('Invalid port')
            sys.exit()
    except ValueError:
        print('Invalid port')
        sys.exit()

    dns_server = DNSResolver(port, forwarder)
    dns_server.run()


if __name__ == '__main__':
    try:
        main()
    except PermissionError:
        print('PermissionError: rights elevation required to bind desired port')
        sys.exit(0)

from natpmp_operation.common_utils  import is_valid_ip_string
from client.network_utils           import get_default_router_address

import argparse
import sys


def process_command_line_params():
    namespace = get_commands_namespace()
    check_ok_settings(namespace)
    return namespace


# Processes the client command-line params, returns a namespace object
def get_commands_namespace():

    # Argument parser from Python 3.5 stdlib
    parser = argparse.ArgumentParser(description="NAT-PMP client to use with both standard v0 and custom v1.")

    # Argument group for either v0 or v1
    group_ver = parser.add_mutually_exclusive_group(required=True)
    group_ver.add_argument('-v0', action='store_true', help="Use NAT-PMP version 0 (supported by all NAT-PMP enabled routers).")
    group_ver.add_argument('-v1', action='store_true', help="Use NAT-PMP version 1 (custom protocol specification with some enhancements).")

    # Argument group for either info or request
    op_group = parser.add_mutually_exclusive_group(required=True)
    op_group.add_argument('-info', action='store_true', help="Send a NAT-PMP discovery packet and display the response")
    op_group.add_argument('-req', nargs=3, help="Issue a NAT-PMP port mapping request.", metavar=("private_port", "public_port", "TCP/UDP"))

    parser.add_argument('-l', nargs='?', help="Lifetime for the port mapping request.", metavar="seconds", type=int, default=7200, const=7200)
    parser.add_argument('-ips', nargs='+', help="When issuing a v1 request, must include the public interfaces to map into.", metavar="ip_address")

    parser.add_argument('-tls', nargs=2, help="Send a secured request with v1, using the selected certificate and private key.",
                        metavar=('cert_path', 'key_path'), type=argparse.FileType('rb'))

    parser.add_argument('-g', nargs='?', help="Gateway to send the request to. If not specified, will try to guess the default gateway.",
                        metavar="gateway_address", const=None)

    return parser.parse_args()


# Check that the user settings from the namespace are acceptable
def check_ok_settings(namespace):

    # If -req is set, check that all of its arguments are correct
    if namespace.req is not None:
        try:
            priv_port = int(namespace.req[0])
            if not 1 <= priv_port <= 65535:
                raise ValueError
        except ValueError:
            sys.exit("The private port must be an integer between 1 and 65535.")

        try:
            pub_port = int(namespace.req[1])
            if not 1 <= pub_port <= 65535:
                raise ValueError
        except ValueError:
            sys.exit("The private port must be an integer between 1 and 65535.")

        if namespace.req[2].upper() not in ['TCP', 'UDP']:
            sys.exit("The protocol for the mapping must be either TCP or UDP")

    if namespace.tls and namespace.v0:
        sys.exit("NAT-PMP v0 does not support secure requests.")

    if namespace.ips and namespace.v0:
        print("Warning: specifying public IPs when sending a v0 request will have no effect.")

    # If -l is set, check that it's a positive integer
    if namespace.l <= 0:
        sys.exit("The lifetime must be a positive amount.")

    if namespace.v1 and namespace.req and not namespace.ips:
        sys.exit("Must specify IPv4 addresses to map ports into when issuing a v1 request.")

    # If -ips is set, check that all of them are valid
    if namespace.ips is not None:
        for ip in namespace.ips:
            if not is_valid_ip_string(ip):
                sys.exit("IP address %s from -l is not a valid address." % ip)

    # If -g is set, check that it's a valid address
    if namespace.g is not None:
        if not is_valid_ip_string(namespace.g):
            sys.exit("IP address %s from -g is not a valid address." % namespace.g)
    else:
        namespace.g = get_default_router_address()

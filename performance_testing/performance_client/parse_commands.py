import argparse
import sys

from natpmp_operation.common_utils import is_valid_ip_string


def get_namespace():
    parser = argparse.ArgumentParser(description="NAT-PMP performance meter.")

    parser.add_argument('-v', nargs=1, help="Version of the NAT-PMP protocol to use.", metavar="version", type=int,
                        default=0)
    parser.add_argument('-n', nargs=1, help="Number of requests to send.", metavar="count", type=int,
                        default=1000)
    parser.add_argument('-g', nargs=1, help="Gateway address.", metavar="gateway")
    parser.add_argument('-op', nargs=1, help="Operation to do against the gateway.", metavar="info/req")
    parser.add_argument('-ips', nargs='+',
                        help="When issuing a v1 request, must include the public interfaces to map into.",
                        metavar="ip_address")
    parser.add_argument('-sec', nargs=2,
                        help="Send a secured request with v1, using the selected certificate and private key.",
                        metavar=('cert_path', 'key_path'), type=argparse.FileType('rb'))

    namespace = parser.parse_args()
    check_params_ok(namespace)
    return namespace


def check_params_ok(namespace):
    if not 0 <= namespace.v <= 1:
        sys.exit("Only version 0 and 1 are currently supported.")

    if namespace.n < 1:
        sys.exit("Why do you want to send less than 1 request?")

    if not namespace.g or not is_valid_ip_string(namespace.g):
        sys.exit("Please, provide a valid gateway address using the -g flag.")

    if not namespace.op or namespace.op not in ["info", "req"]:
        sys.exit("Please, provide a valid operation using the -op flag (info/req)")

    if namespace.v == 1:
        if not namespace.ips or any(not is_valid_ip_string(x) for x in namespace.ips.split()):
            sys.exit("At least one argument provided by the -ips flag is not a valid IP address.")

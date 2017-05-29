#!/usr/bin/env python3

from natpmp_operation.natpmp_logic_common import NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP, NATPMP_RESULT_OK, NATPMP_RESULT_VERSION_NOT_SUPPORTED, NATPMP_RESULT_NOT_AUTHORIZED, \
                                                   NATPMP_RESULT_NETWORK_ERROR, NATPMP_RESULT_INSUFFICIENT_RESOURCES, NATPMP_RESULT_OPCODE_NOT_SUPPORTED, NATPMP_RESULT_MULTIASSIGN_FAILED, \
                                                   NATPMP_RESULT_TLS_ONLY, NATPMP_RESULT_BAD_CERT
from natpmp_operation.security_module import load_private_key_asking_for_password, sign_and_cipher_data_with_nonce, decipher_and_check_signature_and_nonce
from natpmp_packets.NATPMPCertHandshake import NATPMPCertHandshake
from natpmp_packets.NATPMPRequest import NATPMPRequest
from natpmp_operation.common_utils import is_valid_ip_string
from client.network_utils import send_and_receive_with_timeout

from cryptography.hazmat.backends           import default_backend
from cryptography                           import x509

from random                                 import randint

import socket
import datetime
import argparse
import sys
import numpy

NATPMP_PORT = 5351
RESULT_TIMED_OUT = -1


def get_namespace():
    parser = argparse.ArgumentParser(description="NAT-PMP performance meter.")

    parser.add_argument('-v', nargs='?', help="Version of the NAT-PMP protocol to use.", metavar="version", type=int,
                        default=0)
    parser.add_argument('-n', nargs='?', help="Number of requests to send.", metavar="count", type=int,
                        default=1000)
    parser.add_argument('-t', nargs='?', help="Amount of time (milliseconds) to consider a request as timed out.", metavar="millis", type=int,
                        default=1000)
    parser.add_argument('-g', nargs='?', help="Gateway address.", metavar="gateway")
    parser.add_argument('-op', nargs='?', help="Operation to do against the gateway.", metavar="info/req")
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
        sys.exit("Please, provide a request count greater than zero.")

    if namespace.t < 1:
        sys.exit("Please, provide a timeout amount greater than zero milliseconds.")

    if not namespace.g or not is_valid_ip_string(namespace.g):
        sys.exit("Please, provide a valid gateway address using the -g flag.")

    if not namespace.op or namespace.op not in ["info", "req"]:
        sys.exit("Please, provide a valid operation using the -op flag (info/req)")

    if namespace.v == 1 and namespace.op == "req":
        if not namespace.ips or any(not is_valid_ip_string(x) for x in namespace.ips):
            sys.exit("At least one argument provided by the -ips flag is not a valid IP address.")

if __name__ == "__main__":
    namespace = get_namespace()

    # Init params from the namespace
    version = namespace.v
    reqs_to_send = namespace.n
    timeout_amount = namespace.t
    operation = NATPMP_OPCODE_INFO if namespace.op == "info" else NATPMP_OPCODE_MAPUDP
    router_addr = namespace.g
    ips = namespace.ips
    use_tls = bool(namespace.sec)
    if use_tls:
        cert_file = namespace.sec[0]
        key_file = namespace.sec[1]

    # Init network socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setblocking(0)
    udp_sock.connect((router_addr, NATPMP_PORT))

    # Init secure params if needed
    if use_tls:
        cert_bytes = cert_file.read()
        private_key = load_private_key_asking_for_password(key_file.name)

    # Init requests
    if use_tls:
        cert_exchange_request = NATPMPCertHandshake(version, 3, 0, bytearray(8), cert_bytes)

    if operation == NATPMP_OPCODE_INFO:
        operation_request = NATPMPRequest(version, operation)
    elif version == 0:
        operation_request = NATPMPRequest(version, operation, 0, 0, 0, 3600)
    else:
        operation_request = NATPMPRequest(version, operation, 0, 0, 0, 3600, ips)

    # Init result params
    result_codes = {
        NATPMP_RESULT_OK: 0,
        NATPMP_RESULT_VERSION_NOT_SUPPORTED: 0,
        NATPMP_RESULT_NOT_AUTHORIZED: 0,
        NATPMP_RESULT_NETWORK_ERROR: 0,
        NATPMP_RESULT_INSUFFICIENT_RESOURCES: 0,
        NATPMP_RESULT_OPCODE_NOT_SUPPORTED: 0,
        NATPMP_RESULT_MULTIASSIGN_FAILED: 0,
        NATPMP_RESULT_TLS_ONLY: 0,
        NATPMP_RESULT_BAD_CERT: 0,
        RESULT_TIMED_OUT: 0,
    }

    response_times = []

    for i in range(reqs_to_send):
        if i > 0 and i % 100 == 0:
            print("Sent %d requests." % i, flush=True)

        if use_tls:
            req_handshake_bytes = cert_exchange_request.to_bytes()
            time_start_handshake = datetime.datetime.now()
            data_handshake, _ = send_and_receive_with_timeout(udp_sock, router_addr, req_handshake_bytes, timeout_amount)
            time_end_handshake = datetime.datetime.now()

            if data_handshake is None:
                result_codes[RESULT_TIMED_OUT] += 1
                continue

            res_handshake = int.from_bytes(data_handshake[2:4], 'big')
            if res_handshake != NATPMP_RESULT_OK:
                result_codes[res_handshake] += 1
                continue

            server_cert_bytes = data_handshake[12:]
            nonce = data_handshake[4:12]
            # Load the server's cert
            try:
                server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())
            except ValueError:
                server_cert = x509.load_der_x509_certificate(server_cert_bytes, default_backend())

        if operation != NATPMP_OPCODE_INFO:
            operation_request.external_port = randint(1, 65535)
            operation_request.internal_port = randint(1, 65535)

        request_bytes = operation_request.to_bytes()

        if use_tls:
            request_bytes = sign_and_cipher_data_with_nonce(request_bytes, server_cert.public_key(), private_key, nonce)

        time_start_request = datetime.datetime.now()
        data_response, _ = send_and_receive_with_timeout(udp_sock, router_addr, request_bytes, timeout_amount)
        time_end_request = datetime.datetime.now()

        if data_response is None:
            result_codes[RESULT_TIMED_OUT] += 1
            continue

        if use_tls:
            data_response = decipher_and_check_signature_and_nonce(data_response, private_key,  server_cert.public_key(), nonce)

        response_code = int.from_bytes(data_response[2:4], 'big')
        result_codes[response_code] += 1

        time_elapsed = (time_end_request - time_start_request).total_seconds()
        if use_tls:
            time_elapsed += (time_end_handshake - time_start_handshake).total_seconds()

        response_times.append(time_elapsed)

    print("----------------------------------------------------")
    print("\nResponse codes:")

    def print_stats_codes(title, key):
        print("    %s: %d (%.2f%%)" % (title, result_codes[key], result_codes[key] / reqs_to_send * 100))

    print_stats_codes("OK", NATPMP_RESULT_OK)
    print_stats_codes("Version not supported", NATPMP_RESULT_VERSION_NOT_SUPPORTED)
    print_stats_codes("Not authorized", NATPMP_RESULT_NOT_AUTHORIZED)
    print_stats_codes("Network error", NATPMP_RESULT_NETWORK_ERROR)
    print_stats_codes("Insufficient resources", NATPMP_RESULT_INSUFFICIENT_RESOURCES)
    print_stats_codes("Opcode not supported", NATPMP_RESULT_OPCODE_NOT_SUPPORTED)
    print_stats_codes("Multiassign failed", NATPMP_RESULT_MULTIASSIGN_FAILED)
    print_stats_codes("Secure requests only", NATPMP_RESULT_TLS_ONLY)
    print_stats_codes("Bad certificate", NATPMP_RESULT_BAD_CERT)
    print_stats_codes("Timed out", RESULT_TIMED_OUT)

    avg_time = sum(response_times) / len(response_times)
    median_time = numpy.median(response_times)
    stdev = numpy.std(response_times)
    max_time = max(response_times)
    min_time = min(response_times)

    print("\nResponse times:")
    print("    Average: %.5f s (%.2f ms)" % (avg_time, avg_time * 1000))
    print("    Median: %.5f s (%.2f ms)" % (median_time, median_time * 1000))
    print("    Std. deviation: %.5f s (%.2f ms)" % (stdev, stdev * 1000))
    print("    Max: %.5f s (%.2f ms)" % (max_time, max_time * 1000))
    print("    Min: %.5f s (%.2f ms)" % (min_time, min_time * 1000))
    print("    Requests per second: %.2f (avg)" % (1.0 / avg_time))

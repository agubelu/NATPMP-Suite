from client.command_processor               import process_command_line_params
from client                                 import normalized_request
from client.network_utils                   import send_request_get_response

from cryptography.hazmat.backends           import default_backend
from cryptography                           import x509

from natpmp_packets.NATPMPCertHandshake     import NATPMPCertHandshake
from natpmp_operation.security_module       import load_private_key_asking_for_password, sign_and_cipher_data_with_nonce, decipher_and_check_signature_and_nonce

from natpmp_operation.natpmp_logic_common   import NATPMP_RESULT_VERSION_NOT_SUPPORTED, NATPMP_RESULT_BAD_CERT, NATPMP_RESULT_INSUFFICIENT_RESOURCES, \
                                                   NATPMP_RESULT_MULTIASSIGN_FAILED, NATPMP_RESULT_NETWORK_ERROR, NATPMP_RESULT_NOT_AUTHORIZED, \
                                                   NATPMP_RESULT_OK, NATPMP_RESULT_OPCODE_NOT_SUPPORTED, NATPMP_RESULT_TLS_ONLY, NATPMP_OPCODE_INFO, \
                                                   NATPMP_OPCODE_MAPTCP, NATPMP_OPCODE_MAPUDP

import sys


RESCODES_MSGS = {
    NATPMP_RESULT_OK: "The request was accepted by the server.",
    NATPMP_RESULT_OPCODE_NOT_SUPPORTED: "The server didn't recognise the requested operation",
    NATPMP_RESULT_VERSION_NOT_SUPPORTED: "The server does not support this version of the NAT-PMP protocol",
    NATPMP_RESULT_NOT_AUTHORIZED: "The client is not authorized to fulfill the request.",
    NATPMP_RESULT_INSUFFICIENT_RESOURCES: "The server is temporarily out of resources to fulfill the request.",
    NATPMP_RESULT_NETWORK_ERROR: "The server could not fulfill the request due to a network error.",
    NATPMP_RESULT_MULTIASSIGN_FAILED: "The server denied the multi-assign request, try requesting them individually.",
    NATPMP_RESULT_BAD_CERT: "The server rejected the client's certificate.",
    NATPMP_RESULT_TLS_ONLY: "The server is only accepting secure requests.",
}

OPERATIONS_DESC = {
    NATPMP_OPCODE_INFO: "Information request - NAT-PMP discovery",
    NATPMP_OPCODE_MAPTCP: "TCP mapping",
    NATPMP_OPCODE_MAPUDP: "UDP mapping",
}

if __name__ == "__main__":

    if "gui" in sys.argv or len(sys.argv) == 1:
        pass  # TODO launch the client GUI
    else:
        # Get the namespace from the command line
        namespace = process_command_line_params()

        # Normalize the namespace into a common object for both the command line and the GUI
        req_norm = normalized_request.from_namespace(namespace)

        # If the user requested to send a secure packet, perform the handshake first
        if req_norm.use_tls:
            key = load_private_key_asking_for_password(req_norm.tls_key.name)

            print("Performing the initial handshake with the server...")
            handshake_req = NATPMPCertHandshake(req_norm.version, 3, 0, bytearray(8), req_norm.tls_cert.read())

            try:
                data = send_request_get_response(req_norm.router_addr, handshake_req)
            except ConnectionRefusedError:
                sys.exit("The router is not accepting NAT-PMP requests")

            if data is None:
                sys.exit("The server did not reply.")

            # Convert the received data to a response
            handshake_response = normalized_request.server_bytes_to_object(data)

            # Check that the handshake has been accepted
            hand_result = int.from_bytes(data[2:4], 'big')

            if hand_result != NATPMP_RESULT_OK:
                sys.exit("The handshake operation failed: %s" % RESCODES_MSGS[hand_result])

            # Handshake OK
            server_cert_bytes = handshake_response.cert_bytes
            nonce = handshake_response.nonce

            # Load the server's cert
            try:
                server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())
            except ValueError:
                try:
                    server_cert = x509.load_der_x509_certificate(server_cert_bytes, default_backend())
                except ValueError:
                    sys.exit("Handshake was OK but the server's certificate could not be loaded.")

            print("Handshake OK, nonce: 0x" + nonce.hex().upper())

        # Now, load the request into an object
        request_obj = req_norm.to_request_object()
        request_bytes = request_obj.to_bytes()

        # If it's a secure packet, sign and cipher it
        if req_norm.use_tls:
            request_bytes = sign_and_cipher_data_with_nonce(request_bytes, server_cert.public_key(), key, nonce)

        try:
            response_data = send_request_get_response(req_norm.router_addr, request_bytes, True)
        except ConnectionRefusedError:
            sys.exit("The server is not accepting NAT-PMP requests.")

        if response_data is None:
            sys.exit("The server did not reply.")

        # If it's a secure packet, decipher and check signature
        if req_norm.use_tls:
            response_data = decipher_and_check_signature_and_nonce(response_data, key,  server_cert.public_key(), nonce)

        rescode = int.from_bytes(response_data[2:4], 'big')

        if rescode != NATPMP_RESULT_OK:
            sys.exit("The server refused the operation: %s" % RESCODES_MSGS[rescode])

        response_object = normalized_request.server_bytes_to_object(response_data)
        original_opcode = response_object.opcode - 128

        print("------------------------\nResponse data:")
        print("NAT-PMP version: %d" % response_object.version)
        print("Operation: %d (%s)" % (original_opcode, OPERATIONS_DESC[original_opcode]))
        print("Seconds since last start: %d" % response_object.epoch)

        if original_opcode == NATPMP_OPCODE_INFO:
            print("External IPv4 addresses: " + str(response_object.addresses).strip("[]"))
        elif original_opcode in [NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP]:
            print("Internal port: %d" % response_object.internal_port)
            print("External port: %d" % response_object.external_port)
            print("Lifetime (seconds): %d" % response_object.lifetime)

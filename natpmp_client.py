from client.command_processor           import process_command_line_params
from client                             import normalized_request
from client.network_utils               import send_request_get_response

from cryptography.hazmat.backends       import default_backend
from cryptography                       import x509

from natpmp_packets.NATPMPCertHandshake import NATPMPCertHandshake
from natpmp_operation.security_module   import load_private_key_asking_for_password, sign_and_cipher_data_with_nonce

import sys


if __name__ == "__main__":

    if "gui" in sys.argv or len(sys.argv) == 1:
        pass  # TODO launch the client GUI
    else:
        # Get the namespace from the command line
        namespace = process_command_line_params()

        # Normalize the namespace into a common object for both the command line and the GUI
        req_norm = normalized_request.from_namespace(namespace)

        if req_norm.use_tls:
            key = load_private_key_asking_for_password(req_norm.tls_key.name)

            # Do a TLS handshake TODO comprobar que funcione etc etc
            handshake_req = NATPMPCertHandshake(req_norm.version, 3, 0, bytearray(8), req_norm.tls_cert.read())

            try:
                data = send_request_get_response(req_norm.router_addr, handshake_req)
                nonce = data[4:12]
                # Try to decode the cert from the byte data
                try:
                    cert = x509.load_pem_x509_certificate(data[12:], default_backend())
                except ValueError:
                    cert = x509.load_der_x509_certificate(data[12:], default_backend())

            except ConnectionRefusedError:
                sys.exit("The router is not accepting NAT-PMP requests")

            encr_data = sign_and_cipher_data_with_nonce(req_norm.to_request_object().to_bytes(), cert.public_key(), key, nonce)
            data2 = send_request_get_response(req_norm.router_addr, encr_data, raw=True)
        else:
            send_request_get_response(req_norm.router_addr, req_norm.to_request_object())

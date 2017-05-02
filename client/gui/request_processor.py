from natpmp_operation.common_utils      import is_valid_ip_string
from natpmp_operation.security_module   import load_certificate, load_private_key, sign_and_cipher_data_with_nonce, decipher_and_check_signature_and_nonce
from natpmp_packets.NATPMPCertHandshake import NATPMPCertHandshake
from natpmp_client                      import OPERATIONS_DESC, RESCODES_MSGS, NATPMP_RESULT_OK, NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPTCP, NATPMP_OPCODE_MAPUDP
from client.network_utils               import get_default_router_address, send_request_get_response
from client                             import normalized_request

from cryptography.hazmat.backends       import default_backend
from cryptography                       import x509

from datetime                           import datetime, timedelta

from tkinter                            import simpledialog


def process_request(frame):
    frame.reset_info_text()

    # Get the request information
    version = 0 if frame.select_version.var.get() == "NAT-PMP v0 (official)" else 1
    opcode = {
        "NAT-PMP discovery": 0,
        "UDP mapping": 1,
        "TCP mapping": 2,
    }[frame.select_operation.var.get()]

    priv_port = frame.entry_privport.var.get()
    pub_port = frame.entry_pubport.var.get()
    lifetime = frame.entry_lifetime.var.get()
    ips = frame.entry_ips.var.get()
    gateway = frame.entry_gateway.var.get()
    usetls = bool(frame.check_usetls.var.get())
    cert_path = frame.text_cert["text"].replace("\n", "")
    key_path = frame.text_key["text"].replace("\n", "")

    # Check that the provided fields are correct
    field_errors, ok_data = get_errors(version, opcode, priv_port, pub_port, lifetime, ips, gateway, usetls, cert_path, key_path)

    if field_errors:
        for err in field_errors:
            frame.insert_info_line("Error: " + err)

        frame.insert_info_line("")
        frame.insert_info_line("Please, fix the errors and try again.")
        return

    # If we are using TLS, check that the provided files are a valid cert and key
    if usetls:
        tls_errors, cert_obj, key_obj = get_tls_objects(cert_path, key_path)

        if tls_errors:
            for err in tls_errors:
                frame.insert_info_line("Error: " + err)
            frame.insert_info_line("")
            frame.insert_info_line("Please, fix the errors and try again.")
            return

    # Everything is 'kay, create the normalized request and send it
    req = normalized_request.from_dict(ok_data)

    if usetls:
        req.cert_object = cert_obj
        req.key_object = key_obj

    send_request(req, frame)

    if "tls_cert" in ok_data:
        ok_data["tls_cert"].close()

    if "tls_key" in ok_data:
        ok_data["tls_key"].close()


def send_request(request, frame):
    # If the request uses TLS, send the handshake first
    if request.use_tls:
        frame.insert_info_line("Handshaking with %s for a secure request..." % request.router_addr)

        handshake_req = NATPMPCertHandshake(request.version, 3, 0, bytearray(8), request.tls_cert.read())

        try:
            handshake_response_bytes = send_request_get_response(request.router_addr, handshake_req, frame=frame)
        except ConnectionRefusedError:
            frame.insert_info_line("The router is not accepting NAT-PMP requests")
            return

        if handshake_response_bytes is None:
            frame.insert_info_line("The router did not reply.")
            return

        # Convert the received data to a response
        handshake_response = normalized_request.server_bytes_to_object(handshake_response_bytes)

        # Check that the handshake has been accepted
        hand_result = int.from_bytes(handshake_response_bytes[2:4], 'big')
        if hand_result != NATPMP_RESULT_OK:
            frame.insert_info_line("The handshake operation failed: %s" % RESCODES_MSGS[hand_result])
            return

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
                frame.insert_info_line("Handshake was OK but the server's certificate could not be loaded.")
                return

        frame.insert_info_line("Handshake OK, nonce: 0x" + nonce.hex().upper())

    # Load the request into an object
    request_obj = request.to_request_object()
    request_bytes = request_obj.to_bytes()

    if request.use_tls:
        request_bytes = sign_and_cipher_data_with_nonce(request_bytes, server_cert.public_key(), request.key_object, nonce)

    frame.insert_info_line("Sending %sNAT-PMP request to the router..." % ("secure " if request.use_tls else ""))

    try:
        response_data = send_request_get_response(request.router_addr, request_bytes, True, frame=frame)
    except ConnectionRefusedError:
        frame.insert_info_line("The server is not accepting NAT-PMP requests.")
        return

    if response_data is None:
        frame.insert_info_line("The server did not reply.")
        return

    # If it's a secure packet, decipher and check signature
    if request.use_tls:
        response_data = decipher_and_check_signature_and_nonce(response_data, request.key_object, server_cert.public_key(), nonce)

    rescode = int.from_bytes(response_data[2:4], 'big')

    if rescode != NATPMP_RESULT_OK:
        frame.insert_info_line("The server refused the operation: %s" % RESCODES_MSGS[rescode])
        return

    response_object = normalized_request.server_bytes_to_object(response_data)
    original_opcode = response_object.opcode - 128

    frame.insert_info_line("------------------------\nResponse data:")
    frame.insert_info_line("NAT-PMP version: %d" % response_object.version)
    frame.insert_info_line("Operation: %d (%s)" % (original_opcode, OPERATIONS_DESC[original_opcode]))
    frame.insert_info_line("Seconds since last start: %d" % response_object.epoch)

    if original_opcode == NATPMP_OPCODE_INFO:
        frame.insert_info_line("External IPv4 addresses: " + str(response_object.addresses).strip("[]"))
    elif original_opcode in [NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP]:
        frame.insert_info_line("Internal port: %d" % response_object.internal_port)
        frame.insert_info_line("External port: %d" % response_object.external_port)
        frame.insert_info_line("Lifetime (seconds): %d (expires at %s)" %
                               (response_object.lifetime, (datetime.now() - timedelta(seconds=response_object.lifetime)).strftime("%Y-%m-%d %H:%M:%S")))


##########################################################################################################
##########################################################################################################
##########################################################################################################

def get_errors(version, opcode, priv_port, pub_port, lifetime, ips, gateway, usetls, cert_path, key_path):
    errors = []

    ok_data = {'version': version, 'opcode': opcode}

    if opcode != 0:
        # It's a request, check the parameters
        try:
            priv_port_int = int(priv_port)
            if not 0 <= priv_port_int <= 65535:
                raise ValueError
            ok_data['private_port'] = priv_port_int
        except ValueError:
            errors.append("The private port must be an integer between 0 and 65535.")

        try:
            pub_port_int = int(pub_port)
            if not 0 <= pub_port_int <= 65535:
                raise ValueError
            ok_data['public_port'] = pub_port_int
        except ValueError:
            errors.append("The public port must be an integer between 0 and 65535.")

        try:
            lifetime_int = int(lifetime)
            if not 0 <= lifetime_int:
                raise ValueError
            ok_data['lifetime'] = lifetime_int
        except ValueError:
            errors.append("The lifetime must be an integer equal to or greater than zero.")

        if version == 1:
            if not ips:
                errors.append("You must provide at least one public IPv4 address for the request.")
            else:
                ok_data['ips'] = []
                for ip in ips.split(","):
                    if not is_valid_ip_string(ip):
                        errors.append("IPv4 address '%s' from public IPs is not a valid address." % ip)
                    else:
                        ok_data['ips'].append(ip)

    if gateway == "" or gateway == "default":
        try:
            gateway = get_default_router_address()
        except IOError:
            errors.append("Could not determine the default gateway, please provide it manually.")
    elif not is_valid_ip_string(gateway):
        errors.append("The gateway '%s' is not a valid IPv4 address." % gateway)

    ok_data['gateway'] = gateway
    ok_data['usetls'] = usetls

    if usetls:
        try:
            ok_data['tls_cert'] = open(cert_path, "rb")
        except IOError:
            errors.append("Cannot read the certificate file.")

        try:
            ok_data['tls_key'] = open(key_path, "rb")
        except IOError:
            errors.append("Cannot read the key file.")

    return errors, ok_data


def get_tls_objects(cert_path, key_path):
    errors = []
    cert = None
    key = None

    try:
        cert = load_certificate(cert_path)
    except ValueError:
        errors.append("The certificate file could not be loaded. Does it contain a valid certificate?")

    if not errors:
        try:
            key = load_private_key(key_path, None)
        except ValueError:
            passw = simpledialog.askstring("Key password", "Please input the private key password:", show="*")
            while True:
                if passw is None:
                    errors.append("Could not decipher the private key.")
                    break
                try:
                    key = load_private_key(key_path, passw)
                    break
                except ValueError:
                    passw = simpledialog.askstring("Key password", "The previous key is not correct, try again:", show="*")

    return errors, cert, key

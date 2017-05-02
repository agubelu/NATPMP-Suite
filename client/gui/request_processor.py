from natpmp_operation.common_utils      import is_valid_ip_string
from natpmp_operation.security_module   import load_certificate, load_private_key
from client.network_utils               import get_default_router_address

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
            with open(cert_path, "rb") as f:
                ok_data['tls_cert'] = f
        except IOError:
            errors.append("Cannot read the certificate file.")

        try:
            with open(key_path, "rb") as f:
                ok_data['tls_key'] = f
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

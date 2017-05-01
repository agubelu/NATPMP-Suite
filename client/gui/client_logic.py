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

    if not check_params_ok(version, opcode, priv_port, pub_port, lifetime, ips, gateway, usetls, cert_path, key_path):
        frame.insert_info_line("")
        frame.insert_info_line("Please, fix the errors and try again.")
        return


def check_params_ok(version, opcode, priv_port, pub_port, lifetime, ips, gateway, usetls, cert_path, key_path):
    return False

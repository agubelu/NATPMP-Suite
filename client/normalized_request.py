# Used to normalized requests from both the command line and the graphical interface into a common object
# that will be mapped into NAT-PMP requests.

from natpmp_operation import natpmp_logic_common


# Return a CommonClientRequest from a command namespace processed from the command line
def from_namespace(namespace):
    # We assume here that the stuff in the namespace is already checked and correct!
    version = 0 if namespace.v0 else 1

    if namespace.info:
        opcode = natpmp_logic_common.NATPMP_OPCODE_INFO
        priv_port = None
        pub_port = None
        lifetime = None
        public_ips = None
    else:
        # namespace.req must be set and checked for correctness
        opcode = natpmp_logic_common.NATPMP_OPCODE_MAPTCP if namespace.req[2].upper() == "TCP" else natpmp_logic_common.NATPMP_OPCODE_MAPUDP
        priv_port = int(namespace.req[0])
        pub_port = int(namespace.req[1])
        lifetime = int(namespace.l)
        public_ips = namespace.ips

    use_tls = True if namespace.tls else False  # Note that just doing use_tls = namespace.tls might result in setting a None value
    tls_cert = namespace.tls[0] if namespace.tls else None
    tls_key = namespace.tls[1] if namespace.tls else None
    router = namespace.g

    return CommonClientRequest(version, opcode, priv_port, pub_port, lifetime, public_ips, use_tls, tls_cert, tls_key, router)


class CommonClientRequest:

    def __init__(self, version, opcode, private_port, public_port, lifetime, public_ips, use_tls, tls_cert, tls_key, router_addr):
        self.version = version
        self.opcode = opcode
        self.private_port = private_port
        self.public_port = public_port
        self.lifetime = lifetime
        self.public_ips = public_ips
        self.use_tls = use_tls
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.router_addr = router_addr

    def __str__(self):
        return "< Normalized request: ver=%s, opcode=%s, private_port=%s, public_port=%s, lifetime=%s, public_ips=%s, use_tls=%s, tls_cert=%s, tls_key=%s, router=%s >" % \
                (str(self.version), str(self.opcode), str(self.private_port), str(self.public_port), str(self.lifetime),
                 str(self.public_ips), self.use_tls, str(self.tls_cert), str(self.tls_key), self.router_addr)

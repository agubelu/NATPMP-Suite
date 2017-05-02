# Used to normalized requests from both the command line and the graphical interface into a common object
# that will be mapped into NAT-PMP requests.

from natpmp_operation                       import natpmp_logic_common

from natpmp_packets.NATPMPRequest           import NATPMPRequest
from natpmp_packets                         import BaseNATPMPResponse, NATPMPInfoResponse, NATPMPMappingResponse, NATPMPCertHandshake
from natpmp_operation.server_exceptions     import MalformedPacketException


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

    use_tls = bool(namespace.tls)
    tls_cert = namespace.tls[0] if namespace.tls else None
    tls_key = namespace.tls[1] if namespace.tls else None
    router = namespace.g

    return CommonClientRequest(version, opcode, priv_port, pub_port, lifetime, public_ips, use_tls, tls_cert, tls_key, router)


# Returns the adequate Response object for the bytes received by the server
def server_bytes_to_object(byte_data):
    if len(byte_data) < 4:
        raise MalformedPacketException("Data received from server is too short")

    opcode = byte_data[1]
    result = int.from_bytes(byte_data[2:4], 'big')

    if result == natpmp_logic_common.NATPMP_RESULT_VERSION_NOT_SUPPORTED:
        return BaseNATPMPResponse.from_bytes(byte_data)
    elif result == natpmp_logic_common.NATPMP_RESULT_OPCODE_NOT_SUPPORTED:
        return BaseNATPMPResponse.BaseNATPMPResponse(byte_data[0], opcode, result)
    elif opcode - 128 == natpmp_logic_common.NATPMP_OPCODE_INFO:
        return NATPMPInfoResponse.from_bytes(byte_data)
    elif opcode - 128 == natpmp_logic_common.NATPMP_OPCODE_SENDCERT:
        return NATPMPCertHandshake.from_bytes(byte_data)
    elif opcode - 128 in [natpmp_logic_common.NATPMP_OPCODE_MAPUDP, natpmp_logic_common.NATPMP_OPCODE_MAPTCP]:
        return NATPMPMappingResponse.from_bytes(byte_data)


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

    def to_request_object(self):
        if self.opcode == natpmp_logic_common.NATPMP_OPCODE_SENDCERT:
            # Current request is a cert handshake
            return NATPMPCertHandshake.NATPMPCertHandshake(self.version, self.opcode, 0, self.tls_cert.read())
        elif self.opcode == natpmp_logic_common.NATPMP_OPCODE_INFO:
            # Current request is a info request
            return NATPMPRequest(self.version, self.opcode)

        # Else, it is a standard NAT-PMP request
        if self.version == 0:
            # V0 without external ips
            return NATPMPRequest(self.version, self.opcode, 0, self.private_port, self.public_port, self.lifetime)
        else:
            # V1 with external ips
            return NATPMPRequest(self.version, self.opcode, 0, self.private_port, self.public_port, self.lifetime, self.public_ips)

from natpmp_packets.BaseNATPMPPacket    import BaseNATPMPPacket
from natpmp_operation.server_exceptions import MalformedPacketException


def from_bytes(byte_data):

    if len(byte_data) < 10:
        raise MalformedPacketException("Received handshake packet is too short.")

    version = byte_data[0]
    opcode = byte_data[1]
    reserved = int.from_bytes(byte_data[2:4], 'big')
    nonce = byte_data[4:12]
    cert_bytes = byte_data[12:]

    return NATPMPCertHandshake(version, opcode, reserved, nonce, cert_bytes)


class NATPMPCertHandshake(BaseNATPMPPacket):

    def __init__(self, version, opcode, reserved, nonce, cert_bytes):
        self.version = version
        self.opcode = opcode
        self.reserved = reserved
        self.nonce = nonce
        self.cert_bytes = cert_bytes

    def to_bytes(self):
        res = bytearray()
        res += self.version.to_bytes(1, 'big')
        res += self.opcode.to_bytes(1, 'big')
        res += self.reserved.to_bytes(2, 'big')
        res += self.nonce
        res += self.cert_bytes

        return res

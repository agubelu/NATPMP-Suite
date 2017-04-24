from natpmp_packets.BaseNATPMPResponse      import BaseNATPMPResponse
from natpmp_operation.server_exceptions     import MalformedPacketException


def from_bytes(byte_data):
    if len(byte_data) != 16:
        raise MalformedPacketException("The byte data does not represent a valid response")

    version = byte_data[0]
    opcode = byte_data[1]
    result = int.from_bytes(byte_data[2:4], 'big')
    epoch = int.from_bytes(byte_data[4:8], 'big')
    internal_port = int.from_bytes(byte_data[8:10], 'big')
    external_port = int.from_bytes(byte_data[10:12], 'big')
    lifetime = int.from_bytes(byte_data[12:16], 'big')

    res = NATPMPMappingResponse(version, opcode, result, internal_port, external_port, lifetime)
    res.epoch = epoch
    return res


class NATPMPMappingResponse(BaseNATPMPResponse):

    def __init__(self, version, opcode, result, internal_port, external_port, lifetime):
        BaseNATPMPResponse.__init__(self, version, opcode, result)
        self.internal_port = internal_port
        self.external_port = external_port
        self.lifetime = lifetime

    def to_bytes(self):
        res = BaseNATPMPResponse.to_bytes(self)
        res += self.internal_port.to_bytes(2, 'big')
        res += self.external_port.to_bytes(2, 'big')
        res += self.lifetime.to_bytes(4, 'big')
        return res

    def __str__(self):
        return "<NAT-PMP RESPONSE> { version: %s, opcode: %s, result: %s, epoch: %s, internal_port: %s, external_port: %s, lifetime: %s }" % \
               (str(self.version), str(self.opcode), str(self.result), str(self.epoch), str(self.internal_port), str(self.external_port), str(self.lifetime))

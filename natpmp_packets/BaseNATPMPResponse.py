from natpmp_packets.BaseNATPMPPacket        import BaseNATPMPPacket
from natpmp_operation.server_exceptions     import MalformedPacketException

import time


def from_bytes(byte_data):
    if len(byte_data) != 8:
        raise MalformedPacketException("The byte data does not represent a valid response")

    version = byte_data[0]
    opcode = byte_data[1]
    result = int.from_bytes(byte_data[2:4], 'big')
    epoch = int.from_bytes(byte_data[4:8], 'big')

    res = BaseNATPMPResponse(version, opcode, result)
    res.epoch = epoch
    return res


class BaseNATPMPResponse(BaseNATPMPPacket):

    def __init__(self, version, opcode, result):
        self.version = version
        self.opcode = opcode
        self.result = result
        from natpmp_daemon import DAEMON_START_TIME
        self.epoch = int(time.time() - DAEMON_START_TIME)

    def to_bytes(self):
        res = bytearray()
        res += self.version.to_bytes(1, 'big')
        res += self.opcode.to_bytes(1, 'big')
        res += self.result.to_bytes(2, 'big')
        res += self.epoch.to_bytes(4, 'big')
        return res

    def __str__(self):
        return "<NAT-PMP RESPONSE> { version: %s, opcode: %s, result: %s, epoch: %s }" % (str(self.version), str(self.opcode), str(self.result), str(self.epoch))

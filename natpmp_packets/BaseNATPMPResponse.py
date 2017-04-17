from natpmp_packets.BaseNATPMPPacket import BaseNATPMPPacket

import time


class BaseNATPMPResponse(BaseNATPMPPacket):

    def __init__(self, version, opcode, result):
        self.version = version
        self.opcode = opcode
        self.result = result
        from natpmp import DAEMON_START_TIME
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

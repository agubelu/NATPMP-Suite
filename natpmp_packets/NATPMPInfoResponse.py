from natpmp_packets.BaseNATPMPResponse import BaseNATPMPResponse
import socket


class NATPMPInfoResponse(BaseNATPMPResponse):

    def __init__(self, version, opcode, result, addresses):
        BaseNATPMPResponse.__init__(self, version, opcode, result)
        self.addresses = addresses

    def to_bytes(self):
        res = BaseNATPMPResponse.to_bytes(self)

        if self.version == 0:
            res += socket.inet_aton(self.addresses[0])
        else:
            for address in self.addresses:
                res += socket.inet_aton(address)

        return res

    def __str__(self):
        return "<NAT-PMP RESPONSE> { version: %s, opcode: %s, result: %s, epoch: %s, addresses: %s }" % \
               (str(self.version), str(self.opcode), str(self.result), str(self.epoch), str(self.addresses))

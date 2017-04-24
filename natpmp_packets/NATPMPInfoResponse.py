from natpmp_packets.BaseNATPMPResponse      import BaseNATPMPResponse
from natpmp_operation.server_exceptions     import MalformedPacketException

import socket


def from_bytes(byte_data):
    packet_length = len(byte_data)

    if packet_length < 12:
        raise MalformedPacketException("The byte data does not represent a valid response")

    version = byte_data[0]
    opcode = byte_data[1]
    result = int.from_bytes(byte_data[2:4], 'big')
    epoch = int.from_bytes(byte_data[4:8], 'big')

    if version == 0:
        if packet_length != 12:
            raise MalformedPacketException("The byte data does not represent a valid response for v0")

        try:
            addresses = [socket.inet_ntoa(byte_data[8:12])]
        except IOError:
            raise MalformedPacketException("Server didn't return a valid IP address")

    else:
        if packet_length % 4 != 0:
            raise MalformedPacketException("The byte data does not represent a valid response for v1")

        addresses = []
        for i in range((packet_length - 8) // 4):
            ipv4 = byte_data[8 + (i * 4):12 + (i * 4)]

            try:
                ip_str = socket.inet_ntoa(ipv4)
            except IOError:
                raise MalformedPacketException("Server didn't return a valid IP address")

                addresses.append(ip_str)

    res = NATPMPInfoResponse(version, opcode, result, addresses)
    res.epoch = epoch
    return res


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

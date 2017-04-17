from server_exceptions                  import MalformedPacketException
from natpmp_packets.BaseNATPMPPacket    import BaseNATPMPPacket

import socket


def from_bytes(byte_data):

    packet_length = len(byte_data)

    if packet_length < 2:
        raise MalformedPacketException("Received packet is less than 2 bytes long")

    version = byte_data[0]
    opcode = byte_data[1]

    if opcode == 0:  # We are serving an informational request, check that it is exactly 2 bytes long
        if packet_length != 2:
            raise MalformedPacketException("Packet has length different than 2 bytes for opcode = 0")
        return NATPMPRequest(version, opcode)

    # Else, check that it is long enough
    if packet_length < 12:
        raise MalformedPacketException("Received packet is less than 12 bytes long for non-zero opcode")

    reserved = int.from_bytes(byte_data[2:4], byteorder='big')
    internal_port = int.from_bytes(byte_data[4:6], byteorder='big')
    external_port = int.from_bytes(byte_data[6:8], byteorder='big')
    requested_lifetime = int.from_bytes(byte_data[8:12], byteorder='big')

    if version == 0:  # We are serving a request for NAT-PMP v0, check that it is exactly 12 bytes long
        if packet_length != 12:
            raise MalformedPacketException("Packet has length different than 12 bytes for NAT-PMP v0 and opcode > 0")
        return NATPMPRequest(version, opcode, reserved, internal_port, external_port, requested_lifetime)

    # If we've reached here, then it's NAT-PMP v1 with length equal or greater to 12 bytes
    # Check that it contains at least a IPv4 address and has a valid length
    if packet_length < 16 or packet_length % 4 != 0:
        raise MalformedPacketException("Packet has less than 16 bytes and/or does not contain valid IPv4 addresses")

    ipv4_addresses = []
    for i in range((packet_length - 12) // 4):
        ipv4 = byte_data[12+(i*4):16+(i*4)]

        try:
            ip_str = socket.inet_ntoa(ipv4)
        except IOError:
            ip_str = '0.0.0.0'

        ipv4_addresses.append(ip_str)

    return NATPMPRequest(version, opcode, reserved, internal_port, external_port, requested_lifetime, ipv4_addresses)


class NATPMPRequest(BaseNATPMPPacket):

    def __init__(self, version, opcode, reserved=None, internal_port=None, external_port=None, requested_lifetime=None, ipv4_addresses=None):
        self.version = version
        self.opcode = opcode
        self.reserved = reserved
        self.internal_port = internal_port
        self.external_port = external_port
        self.requested_lifetime = requested_lifetime
        self.ipv4_addresses = ipv4_addresses

    def to_bytes(self):
        res = bytearray()

        # Add the version and the opcode, common to all requests
        res += self.version.to_bytes(1, 'big')
        res += self.opcode.to_bytes(1, 'big')

        # If the opcode is 0, finish here (it's an informational request)
        if self.opcode == 0:
            return res

        # Else, add parameters until IPv4 addresses
        res += self.reserved.to_bytes(2, 'big')
        res += self.internal_port.to_bytes(2, 'big')
        res += self.external_port.to_bytes(2, 'big')
        res += self.requested_lifetime.to_bytes(4, 'big')

        # If the version is 0, then finish here (IPv4 addresses are not needed)
        if self.version == 0:
            return res

        # Else, add the addresses
        for ip in self.ipv4_addresses:
            res += socket.inet_aton(ip)

        return res

    def __str__(self):
        return "<NAT-PMP REQUEST> { version: %s, opcode: %s, reserved: %s, internal_port: %s, external_port: %s, requested_lifetime: %s, ipv4s: %s }" % \
               (str(self.version), str(self.opcode), str(self.reserved), str(self.internal_port), str(self.external_port), str(self.requested_lifetime), str(self.ipv4_addresses))
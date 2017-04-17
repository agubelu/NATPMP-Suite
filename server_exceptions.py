# Must occur when a received UDP packet does not fit the NAT-PMP specification
class MalformedPacketException(Exception):
    pass

# Must occur when a desired port is already reserved from other mapping request
class PortAlreadyReservedException(Exception):
    pass


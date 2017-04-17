class BaseNATPMPPacket:

    def __init__(self, address=None, sock=None):
        self.address = address
        self.sock = sock

# Occurs when a received UDP packet does not fit the NAT-PMP specification
class MalformedPacketException(Exception):
    pass


# Occurs when a ciphered packet contains an invalid signature
class InvalidPacketSignatureException(Exception):
    pass


# Occurs when a client-sent certificate is not acceptable
class InvalidCertificateException(Exception):
    pass

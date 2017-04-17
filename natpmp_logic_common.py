from server_exceptions  import MalformedPacketException
from natpmp_packets     import NATPMPRequest
import settings


# Constants definition
NATPMP_OPCODE_INFO = 0
NATPMP_OPCODE_MAPUDP = 1
NATPMP_OPCODE_MAPTCP = 2
NATPMP_OPCODE_SENDCERT = 3

NATPMP_RESULT_OK = 0
NATPMP_RESULT_VERSION_NOT_SUPPORTED = 1
NATPMP_RESULT_NOT_AUTHORIZED = 2
NATPMP_RESULT_NETWORK_ERROR = 3
NATPMP_RESULT_INSUFFICIENT_RESOURCES = 4
NATPMP_RESULT_OPCODE_NOT_SUPPORTED = 5

V0_SUPPORTED_OPCODES = [NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP]
V1_SUPPORTED_OPCODES = [NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP, NATPMP_OPCODE_SENDCERT]

CURRENT_MAPPINGS = {ip: {} for ip in settings.PUBLIC_INTERFACES}


def received_bytes_to_request(data):
    if len(data) < 2:
        raise MalformedPacketException("Packet is less than 2 bytes long (minimum length for a NAT-PMP packet)")

    if data[1] >= 128:
        raise MalformedPacketException("Packet has top bit of opcode set (is a response)")

    if data[0] == 1 and data[1] == 3:
        # This is a certificate handshake from V1 and must be encapsulated on a different object
        # TODO
        pass
    else:
        return NATPMPRequest.from_bytes(data)


def process_request(request):
    print(CURRENT_MAPPINGS)


########################################################################################################################################
########################################################################################################################################
########################################################################################################################################


# Checks whether a port (be it TCP or UDP) is assigned to a client in a certain public interface
def is_port_assigned_to_client(ip, port, client):
    if port not in CURRENT_MAPPINGS[ip]:
        return False

    return CURRENT_MAPPINGS[ip][port][0]['client'] == client


# Checks whether a port is available to be mapped (that is, it's not already requested and it's within the
# boundaries of mappable ports).
def is_port_free(ip, port):
    return port not in CURRENT_MAPPINGS[ip] and port not in settings.EXCLUDED_PORTS \
           and port in range(settings.MAX_ALLOWED_MAPPABLE_PORT, settings.MAX_ALLOWED_MAPPABLE_PORT + 1)


# Checks whether a client can map a certain port
def is_port_mappable_for_client(ip, port, client):
    return is_port_free(ip, port) or is_port_assigned_to_client(ip, port, client)

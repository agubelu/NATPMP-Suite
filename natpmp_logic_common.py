from server_exceptions                      import MalformedPacketException
from natpmp_packets                         import NATPMPRequest
from natpmp_packets.BaseNATPMPResponse      import BaseNATPMPResponse
from natpmp_packets.NATPMPInfoResponse      import NATPMPInfoResponse
from natpmp_packets.NATPMPMappingResponse   import NATPMPMappingResponse
from network_module                         import send_response
from common_utils                           import printlog, get_future_date

from apscheduler.schedulers.background      import BackgroundScheduler
from apscheduler.triggers.date              import DateTrigger

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

SUPPORTED_OPCODES = {
    0: [NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP],
    1: [NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP, NATPMP_OPCODE_SENDCERT]
}


# Initialize the mapping status to an empty one
CURRENT_MAPPINGS = {ip: {} for ip in settings.PUBLIC_INTERFACES}


# Initialize the scheduler that will take care of removing expired mappings
mapping_scheduler = BackgroundScheduler()
mapping_scheduler.start()


def received_bytes_to_request(data):
    if len(data) < 2:
        raise MalformedPacketException("Packet is less than 2 bytes long (minimum length for a NAT-PMP packet)")

    if data[1] >= 128:
        raise MalformedPacketException("Packet has top bit of opcode set (is a response)")

    if data[0] == 1 and data[1] == 3:
        # TODO This is a certificate handshake from V1 and must be encapsulated on a different object
        pass
    else:
        return NATPMPRequest.from_bytes(data)


def process_request(request):

    req_ver = request.version
    # Check that the requested version is enabled, return the corresponding response if it is not
    if req_ver == 1 and not settings.ALLOW_VERSION_1 or req_ver == 0 and not settings.ALLOW_VERSION_0:
        response = BaseNATPMPResponse(request.version, request.opcode + 128, NATPMP_RESULT_VERSION_NOT_SUPPORTED)
        response.sock = request.sock
        response.address = request.address
        send_response(response)

        printlog("Rejected request from %s: Version %d not supported." % (str(request.address), req_ver))

    # If the version is supported, check that the opcode in the version is supported too
    elif request.opcode not in SUPPORTED_OPCODES[req_ver]:
        request.opcode += 128
        request.reserved = NATPMP_RESULT_OPCODE_NOT_SUPPORTED
        send_response(request)

        printlog("Rejected request from %s: Opcode %d not supported for version %d." % (str(request.address), request.opcode - 128, req_ver))

    # Version and opcode are fine, process the request with the corresponding processor
    else:
        opcode = request.opcode
        if opcode == NATPMP_OPCODE_INFO:
            operation_get_info(request)
        elif (opcode == NATPMP_OPCODE_MAPUDP or opcode == NATPMP_OPCODE_MAPTCP) and request.requested_lifetime != 0:
            operation_do_mapping(request)
        elif (opcode == NATPMP_OPCODE_MAPUDP or opcode == NATPMP_OPCODE_MAPTCP) and request.requested_lifetime == 0 and request.internal_port != 0:
            operation_remove_mapping(request)
        elif (opcode == NATPMP_OPCODE_MAPUDP or opcode == NATPMP_OPCODE_MAPTCP) and request.requested_lifetime == 0 and request.internal_port == 0:
            operation_remove_batch(request)
        elif opcode == NATPMP_OPCODE_SENDCERT:
            operation_exchange_certs(request)

########################################################################################################################################
########################################################################################################################################
########################################################################################################################################
# Protocol operations


# Returns information regarding the public interfaces available for mapping
def operation_get_info(request):
    ip_addresses = settings.PUBLIC_INTERFACES if request.version == 1 else settings.PUBLIC_INTERFACES[0]
    response = NATPMPInfoResponse(request.version, request.opcode + 128, NATPMP_RESULT_OK, ip_addresses)
    response.address = request.address
    response.sock = request.sock
    send_response(response)

    printlog("Discovery request from %s, version %d" % (request.address, request.version))


# Tries to perform a port mapping operation
def operation_do_mapping(request):
    if not check_client_authorization(request):
        return

    client_ip = request.address[0]

    # Get the public IPs to map into
    public_ips = [settings.PUBLIC_INTERFACES[0]] if request.version == 0 else list(set(request.ipv4_addresses))

    # Check that all the requested public IPs are available for mapping
    if not all(ip in settings.PUBLIC_INTERFACES for ip in public_ips):
        send_denied_response(request, NATPMP_RESULT_NOT_AUTHORIZED)
        printlog("Denying request from %s: trying to map into a non-available external interface." % client_ip)
        return

    # TODO check that there is not another mapping for the same private port...
    # TODO differentiate between ports available for renewal and for new mappings

    # Get a port that is mappable for all interfaces
    if len(public_ips) > 1:
        external_port = get_common_available_port(public_ips, client_ip)
    elif request.external_port == 0:
        external_port = get_first_high_available_port(public_ips[0], client_ip)
    else:
        external_port = get_closest_available_port(public_ips[0], request.external_port, client_ip)

    # Check that there is a port available for the client
    if external_port is None:
        send_denied_response(request, NATPMP_RESULT_INSUFFICIENT_RESOURCES)
        printlog("Denying request from %s: not enough free external ports." % client_ip)
        return

    # At this point, the client can map into the requested port
    print(request.opcode)
    proto = 'UDP' if request.opcode == NATPMP_OPCODE_MAPUDP else 'TCP'
    life = get_acceptable_lifetime(request.requested_lifetime)
    for ip in public_ips:
        create_mapping(ip, external_port, proto, client_ip, request.internal_port, life)

    response = NATPMPMappingResponse(request.version, request.opcode + 128, NATPMP_RESULT_OK, request.internal_port, external_port, life)
    response.sock = request.sock
    response.address = request.address
    send_response(response)


def operation_remove_mapping(request):
    pass  #TODO


def operation_remove_batch(request):
    pass  #TODO


def operation_exchange_certs(request):
    pass  #TODO

########################################################################################################################################
########################################################################################################################################
########################################################################################################################################
# Auxiliary methods


# Checks whether a port (be it TCP or UDP) is assigned to a client in a certain public interface
def is_port_assigned_to_client(ip, port, client):
    if port not in CURRENT_MAPPINGS[ip]:
        return False

    return next(iter(CURRENT_MAPPINGS[ip][port].values()))['client'] == client


# Checks whether a port is available to be mapped (that is, it's not already requested and it's within the
# boundaries of mappable ports).
def is_port_free(ip, port):
    return port not in CURRENT_MAPPINGS[ip] and (settings.EXCLUDED_PORTS is None or port not in settings.EXCLUDED_PORTS) \
           and port in range(settings.MIN_ALLOWED_MAPPABLE_PORT, settings.MAX_ALLOWED_MAPPABLE_PORT + 1)


# Checks whether a client can map a certain port
def is_port_mappable_for_client(ip, port, client):
    return is_port_free(ip, port) or is_port_assigned_to_client(ip, port, client)


# Returns a lifetime as per the configuration params and the client request
def get_acceptable_lifetime(requested_lifetime):
    if settings.FIXED_LIFETIME is not None:
        return settings.FIXED_LIFETIME
    elif requested_lifetime > settings.MAX_ALLOWED_LIFETIME:
        return settings.MAX_ALLOWED_LIFETIME
    elif requested_lifetime < settings.MIN_ALLOWED_LIFETIME:
        return settings.MIN_ALLOWED_LIFETIME
    else:
        return requested_lifetime


# Returns the closest available public port for the client who requested it. Returns None if there is no port available.
def get_closest_available_port(ip, port, client):
    if is_port_mappable_for_client(ip, port, client):
        return port

    for i in range(1, max(abs(port - settings.MIN_ALLOWED_MAPPABLE_PORT), abs(port - settings.MAX_ALLOWED_MAPPABLE_PORT)) + 1):
        if is_port_mappable_for_client(ip, (port + i), client):
            return port + i
        elif is_port_mappable_for_client(ip, (port - i), client):
            return port - i

    return None


# Returns the first high port available for mapping, None if there is no port available
def get_first_high_available_port(ip, client):
    for i in range(settings.MAX_ALLOWED_MAPPABLE_PORT, settings.MIN_ALLOWED_LIFETIME - 1, -1):
        if is_port_mappable_for_client(ip, i, client):
            return i

    return None


# Returns an available port for multiple interfaces. None if there is no such port.
def get_common_available_port(ips, client):
    for i in range(settings.MAX_ALLOWED_MAPPABLE_PORT, settings.MIN_ALLOWED_LIFETIME - 1, -1):
        if all(is_port_mappable_for_client(ip, i, client) for ip in ips):
            return i
    return None


# Issues a "non authorized" response if the client cannot perform operations per the config parameters (white/blacklist)
# Returns True if the client is authorized, False otherwise
def check_client_authorization(request):

    ip_addr = request.address[0]

    res = (not settings.BLACKLIST_MODE and not settings.WHITELIST_MODE) or (settings.BLACKLIST_MODE and ip_addr not in settings.BLACKLISTED_IPS) \
           or (settings.WHITELIST_MODE and ip_addr in settings.WHITELISTED_IPS)

    if not res:
        send_denied_response(request, NATPMP_RESULT_NOT_AUTHORIZED)
        printlog("Rejecting request from %s: not authorized." % ip_addr)

    return res


# Returns a "denied" response
def send_denied_response(request, opcode):
    response = NATPMPMappingResponse(request.version, request.opcode + 128, opcode, request.internal_port, 0, 0)
    response.sock = request.sock
    response.address = request.address
    send_response(response)

########################################################################################################################################
########################################################################################################################################
########################################################################################################################################
# Auxiliary mapping methods


# Creates a new mapping in the system
def create_mapping(ip, port, proto, client, internal_port, lifetime):
    # TODO actually create the mapping in nftables

    expiration_date = get_future_date(lifetime)

    # If port doesn't still have a mapping
    if port not in CURRENT_MAPPINGS[ip]:
        CURRENT_MAPPINGS[ip][port] = {proto: {}}

    # If the port already has a mapping from other protocol
    elif proto not in CURRENT_MAPPINGS[ip][port]:
        CURRENT_MAPPINGS[ip][port][proto] = {}

    # The mapping already exists (the dict is not empty), update the expiration time
    if CURRENT_MAPPINGS[ip][port][proto]:
        CURRENT_MAPPINGS[ip][port][proto]['job'].reschedule(DateTrigger(expiration_date))
        printlog("Updating mapping for %s:%d %s per %s request, new expiration time is %s" % (ip, port, proto, client, str(expiration_date)))
    # The mapping does not exist in the dict, create the job
    else:
        job = mapping_scheduler.add_job(remove_mapping, trigger=DateTrigger(expiration_date), args=(ip, port, proto, 'lifetime terminated'))
        CURRENT_MAPPINGS[ip][port][proto] = {'job': job, 'client': client, 'internal_port': internal_port}
        printlog("Creating mapping for %s:%d %s per %s request, expiration time is %s" % (ip, port, proto, client, str(expiration_date)))

    print(CURRENT_MAPPINGS)


# Removes a mapping from the system
def remove_mapping(ip, port, proto, reason):
    # TODO actually destroy the mapping in nftables
    del CURRENT_MAPPINGS[ip][port][proto]  # Remove the dict entry for this public IP, port and protocol

    if not CURRENT_MAPPINGS[ip][port]:
        del CURRENT_MAPPINGS[ip][port]  # If there are no more mappings for that port, remove it from the dict as well

    printlog("Removing mapping for %s:%d %s (%s)" % (ip, port, proto, reason))
    print(CURRENT_MAPPINGS)

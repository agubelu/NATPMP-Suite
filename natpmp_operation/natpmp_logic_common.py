from datetime                                   import datetime

from apscheduler.schedulers.background          import BackgroundScheduler
from apscheduler.triggers.date                  import DateTrigger
from dateutil.tz                                import tzlocal
from natpmp_operation.network_module            import send_response
from natpmp_operation.server_exceptions         import MalformedPacketException, InvalidCertificateException
from natpmp_operation                           import security_module
from cryptography.hazmat.primitives             import serialization

from natpmp_operation.common_utils              import printlog, get_future_date, printerr
from natpmp_packets                             import NATPMPRequest, NATPMPCertHandshake
from natpmp_packets.BaseNATPMPResponse          import BaseNATPMPResponse
from natpmp_packets.NATPMPInfoResponse          import NATPMPInfoResponse
from natpmp_packets.NATPMPMappingResponse       import NATPMPMappingResponse
from natpmp_operation                           import network_management_module

import settings
import os
import pprint


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
NATPMP_RESULT_MULTIASSIGN_FAILED = 6
NATPMP_RESULT_TLS_ONLY = 7
NATPMP_RESULT_BAD_CERT = 8

SUPPORTED_OPCODES = {
    0: [NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP],
    1: [NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP, NATPMP_OPCODE_MAPTCP],
}

if settings.ALLOW_SECURITY_IN_V1:
    SUPPORTED_OPCODES[1].append(NATPMP_OPCODE_SENDCERT)

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

    if data[0] == 1 and data[1] == NATPMP_OPCODE_SENDCERT:
        return NATPMPCertHandshake.from_bytes(data)
    else:
        return NATPMPRequest.from_bytes(data)


def process_request(request):

    req_ver = request.version
    # Check that the requested version is enabled, return the corresponding response if it is not
    if not 0 <= req_ver <= 1 or (req_ver == 1 and not settings.ALLOW_VERSION_1 or req_ver == 0 and not settings.ALLOW_VERSION_0):
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
        elif (opcode == NATPMP_OPCODE_MAPUDP or opcode == NATPMP_OPCODE_MAPTCP) and request.requested_lifetime == 0:
            operation_remove_mappings(request)
        elif opcode == NATPMP_OPCODE_SENDCERT:
            operation_exchange_certs(request)

########################################################################################################################################
########################################################################################################################################
########################################################################################################################################
# Protocol operations


# Returns information regarding the public interfaces available for mapping
def operation_get_info(request):
    if not check_client_authorization(request):
        return

    ip_addresses = settings.PUBLIC_INTERFACES if request.version == 1 else [settings.PUBLIC_INTERFACES[0]]
    response = NATPMPInfoResponse(request.version, request.opcode + 128, NATPMP_RESULT_OK, ip_addresses)
    response.address = request.address
    response.sock = request.sock

    printlog("Discovery request from %s, version %d" % (request.address, request.version))
    send_response(response)


# Tries to perform a port mapping operation
def operation_do_mapping(request):
    if not check_client_authorization(request):
        return

    client_ip = request.address[0]

    # Get the public IPs to map into
    public_ips = [settings.PUBLIC_INTERFACES[0]] if request.version == 0 else list(set(request.ipv4_addresses))
    request_proto = 'TCP' if request.opcode == NATPMP_OPCODE_MAPTCP else 'UDP'
    client_mappings = get_mappings_client(public_ips, [request.internal_port], [request_proto], client_ip)

    # Check that all the requested public IPs are available for mapping
    if not all(ip in settings.PUBLIC_INTERFACES for ip in public_ips):
        send_denied_response(request, NATPMP_RESULT_NOT_AUTHORIZED)
        printlog("Denying request from %s: trying to map into a non-available external interface." % client_ip)
        return

    if len(public_ips) == 1:
        # We're only mapping for a single public interface
        pub_ip = public_ips[0]
        is_new = not client_mappings

        if is_new:
            # We are handling a new mapping request, search for an available port as requested by the client
            if request.external_port == 0:
                # Assign a high port per server preference
                ext_port = get_first_high_available_port([pub_ip], request_proto, client_ip)
            else:
                # Try to assign the closest port to the client's preference
                ext_port = get_closest_available_port([pub_ip], request.external_port, request_proto, client_ip)

            # Check that there is a port available for the client
            if ext_port is None:
                printlog("Denying request from %s: not enough free external ports." % client_ip)
                send_denied_response(request, NATPMP_RESULT_INSUFFICIENT_RESOURCES)
                return

            # At this point, the client can map into the requested port
            life = get_acceptable_lifetime(request.requested_lifetime)

            try:
                create_mapping(pub_ip, ext_port, request_proto, client_ip, request.internal_port, life)
                send_ok_response(request, request.internal_port, ext_port, life)
            except ValueError:
                send_denied_response(request, NATPMP_RESULT_NETWORK_ERROR)

        else:
            # Handling a request for a single mapping that is already mapped for the client's private port
            existing_mapping = client_mappings[0]

            # If the public port matches, then renovate the current mapping
            if existing_mapping['public_port'] == request.external_port:
                life = get_acceptable_lifetime(request.requested_lifetime)
                try:
                    create_mapping(pub_ip, request.external_port, request_proto, client_ip, request.internal_port, life)
                    send_ok_response(request, request.internal_port, existing_mapping['public_port'], life)
                except ValueError:
                    send_denied_response(request, NATPMP_RESULT_NETWORK_ERROR)
            # Else, send the current mapping as an OK response per protocol specification
            else:
                time_dif = (existing_mapping['job'].next_run_time - datetime.now(tzlocal())).total_seconds()
                send_ok_response(request, request.internal_port, existing_mapping['public_port'], int(time_dif))

    else:
        # We are mapping for multiple public interfaces
        # This operation will be available only if all of them are new mappings or are already mapped to the
        # same public port on all interfaces.
        all_new = not client_mappings
        if all_new:
            if request.external_port == 0:
                # Assign a high port per server preference
                ext_port = get_first_high_available_port(public_ips, request_proto, client_ip)
            else:
                # Try to assign the closest port to the client's preference
                ext_port = get_closest_available_port(public_ips, request.external_port, request_proto, client_ip)

            # Check that there is a port available for the client
            if ext_port is None:
                printlog("Denying request from %s: not enough free external ports." % client_ip)
                send_denied_response(request, NATPMP_RESULT_INSUFFICIENT_RESOURCES)
                return

            # At this point, the client can map into the requested port
            life = get_acceptable_lifetime(request.requested_lifetime)
            created_ips = []

            try:
                for ip in public_ips:
                    create_mapping(ip, ext_port, request_proto, client_ip, request.internal_port, life)
                    created_ips.append(ip)
                send_ok_response(request, request.internal_port, ext_port, life)
            except ValueError:
                for ip in created_ips:
                    remove_mapping(ip, ext_port, request_proto, "removing created mappings after error.")
                send_denied_response(request, NATPMP_RESULT_MULTIASSIGN_FAILED)

        else:
            # There are mappings on some/all interfaces, check that all of the requested mappings can be updated
            # That is, there are already as many mappings as requested, and all of them are bound to the same external port
            # all_updatable = len(client_mappings) == len(public_ips) and len(set(m['public_port'] for m in client_mappings)) == 1
            all_updatable = len(set(m['public_port'] for m in client_mappings)) == 1

            if all_updatable:
                pub_port = client_mappings[0]['public_port']
                life = get_acceptable_lifetime(request.requested_lifetime)
                created_ips = []

                try:
                    for ip in public_ips:
                        create_mapping(ip, pub_port, request_proto, client_ip, request.internal_port, life)
                    send_ok_response(request, request.internal_port, pub_port, life)
                except ValueError:
                    for ip in created_ips:
                        remove_mapping(ip, pub_port, request_proto, "removing created mappings after error.")
                    send_denied_response(request, NATPMP_RESULT_MULTIASSIGN_FAILED)

            else:
                send_denied_response(request, NATPMP_RESULT_MULTIASSIGN_FAILED)


def operation_remove_mappings(request):
    if not check_client_authorization(request):
        return

    client_ip = request.address[0]
    request_proto = 'TCP' if request.opcode == NATPMP_OPCODE_MAPTCP else 'UDP'

    # Get the public IPs to remove maps from
    public_ips = [settings.PUBLIC_INTERFACES[0]] if request.version == 0 else list(set(request.ipv4_addresses))

    # Get the client's private port to remove mappings from
    internal_port = request.internal_port

    # Get the range of private ports to scan for mappings from the client
    # If the private port is different from 0, then the client only wants to remove mappings for that private port
    # If it's set to 0, then the client wants to remove all of his mapping for the requested interfaces.
    private_port_range = [internal_port] if internal_port != 0 else range(settings.MIN_ALLOWED_MAPPABLE_PORT, settings.MAX_ALLOWED_MAPPABLE_PORT + 1)

    mappings = get_mappings_client(public_ips, private_port_range, [request_proto], client_ip)

    # Remove as many mappings as possible, return OK if they could all be deleted.

    deletions_ok = []

    for mapping in mappings:

        try:
            remove_mapping(mapping['ip'], mapping['public_port'], mapping['proto'], 'client request')
            mapping['job'].remove()
            deletions_ok.append(True)
        except ValueError:
            deletions_ok.append(False)

    if all(deletions_ok):
        send_ok_response(request, internal_port, 0, 0)
    else:
        # Send a denied response
        resp = NATPMPRequest.NATPMPRequest(request.version, request.opcode + 128, NATPMP_RESULT_NETWORK_ERROR, request.internal_port, request.external_port,
                                           0, request.ipv4_addresses if request.version == 1 else None)
        resp.sock = request.sock
        resp.address = request.address
        send_response(resp)


def operation_exchange_certs(request):
    if not check_client_authorization(request, handshake=True):
        return

    client_ip = request.address[0]

    # Check that the client sent a valid cert
    # The security module check that it's emmited from us if strict cert checking is active
    try:
        cert = security_module.get_cert_from_bytes(request.cert_bytes)
    except InvalidCertificateException as e:
        printlog("Denying handshake from %s: %s" % (client_ip, str(e)))
        send_denied_handshake_response(request, NATPMP_RESULT_BAD_CERT)
        return

    # Check that the cert matches the client's IP address
    if not security_module.is_cert_valid_for_ip(cert, client_ip):
        printlog("Denying handshake from %s: Certificate not valid for the client's IP." % client_ip)
        send_denied_handshake_response(request, NATPMP_RESULT_BAD_CERT)
        return

    # Send the response first (to not trigger deletion from TLS-enabled IPs)
    client_nonce = os.urandom(8)
    response = NATPMPCertHandshake.NATPMPCertHandshake(request.version, request.opcode + 128, NATPMP_RESULT_OK, client_nonce, security_module.ROOT_CERTIFICATE.public_bytes(serialization.Encoding.PEM))
    response.sock = request.sock
    response.address = request.address
    send_response(response)
    printlog("Accepting handshake for %s" % client_ip)

    # Then add the cert to the TLS-allowed IPs
    security_module.add_ip_to_tls_enabled(client_ip, cert, client_nonce)

########################################################################################################################################
########################################################################################################################################
########################################################################################################################################
# Auxiliary methods


# Checks if a NEW mapping request can be fulfulled for a port, public IP, protocol and client
def is_new_mapping_available(ip, port, proto, client):
    # Check if the public port is mappable per settings configuration
    port_config = (settings.EXCLUDED_PORTS is None or port not in settings.EXCLUDED_PORTS) \
                  and port in range(settings.MIN_ALLOWED_MAPPABLE_PORT, settings.MAX_ALLOWED_MAPPABLE_PORT + 1)

    if not port_config:
        return False

    # Check if the port is not yet assigned for that public IP (then it can be assigned right away)
    if port not in CURRENT_MAPPINGS[ip]:
        return True

    # If we've reached here then the port is already mapped, it can only be mapped again if the proto is not mapped
    if proto in CURRENT_MAPPINGS[ip][port]:
        return False

    # So, there is a mapping but not for this protocol, check that its companion port is reserved by the client.
    comp_proto = 'UDP' if proto == 'TCP' else 'TCP'
    return CURRENT_MAPPINGS[ip][port][comp_proto]['client'] == client


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


# Returns the closest available public port for the client who requested a new mapping. Returns None if there is no such port available.
def get_closest_available_port(ips, port, proto, client):
    if all(is_new_mapping_available(ip, port, proto, client) for ip in ips):
        return port

    for i in range(1, max(abs(port - settings.MIN_ALLOWED_MAPPABLE_PORT), abs(port - settings.MAX_ALLOWED_MAPPABLE_PORT)) + 1):
        if all(is_new_mapping_available(ip, (port + i), proto, client) for ip in ips):
            return port + i
        elif all(is_new_mapping_available(ip, (port - i), proto, client) for ip in ips):
            return port - i

    return None


# Returns the first high port available for mapping, None if there is no port available
def get_first_high_available_port(ips, proto, client):
    for i in range(settings.MAX_ALLOWED_MAPPABLE_PORT, settings.MIN_ALLOWED_MAPPABLE_PORT - 1, -1):
        if all(is_new_mapping_available(ip, i, proto, client) for ip in ips):
            return i

    return None


# Returns an available port for multiple interfaces. None if there is no such port.
def get_common_available_port(ips, proto, client):
    for i in range(settings.MAX_ALLOWED_MAPPABLE_PORT, settings.MIN_ALLOWED_MAPPABLE_PORT - 1, -1):
        if all(is_new_mapping_available(ip, i, proto, client) for ip in ips):
            return i
    return None


def get_mappings_dicts():
    res = []
    for ip in CURRENT_MAPPINGS:
        for port in CURRENT_MAPPINGS[ip]:
            for proto in CURRENT_MAPPINGS[ip][port]:
                d = CURRENT_MAPPINGS[ip][port][proto]
                res.append({'ip': ip, 'public_port': port, 'proto': proto, 'internal_port': d['internal_port'], 'job': d['job'], 'client': d['client']})

    return res


def get_mappings_client(ips, private_ports, protos, client):
    return [m for m in get_mappings_dicts() if m['ip'] in ips and m['internal_port'] in private_ports and m['proto'] in protos and m['client'] == client]


# Issues a "non authorized" response if the client cannot perform operations per the config parameters (white/blacklist)
# Returns True if the client is authorized, False otherwise
def check_client_authorization(request, handshake=False):

    ip_addr = request.address[0]

    # Check that the client has authorization per black and whitelist configurations

    auth = (not settings.BLACKLIST_MODE and not settings.WHITELIST_MODE) or (settings.BLACKLIST_MODE and ip_addr not in settings.BLACKLISTED_IPS) \
        or (settings.WHITELIST_MODE and ip_addr in settings.WHITELISTED_IPS)

    if not auth:
        printlog("Rejecting request from %s: not authorized." % ip_addr)

        if not handshake:
            # Standard mapping response
            send_denied_response(request, NATPMP_RESULT_NOT_AUTHORIZED)
        else:
            # Handshake response
            send_denied_handshake_response(request, NATPMP_RESULT_NOT_AUTHORIZED)

        return False

    if not handshake and settings.FORCE_SECURITY_IN_V1 and request.version == 1 and ip_addr not in security_module.TLS_IPS:
        # If the current request is not a handshake, TLS is enforced, and the issuer has not still sent a handshake, deny the response
        printlog("Rejecting request from %s: plain-text request while TLS is enforced." % ip_addr)
        send_denied_response(request, NATPMP_RESULT_TLS_ONLY)
        return False

    return True


# Returns a "denied" mapping response
def send_denied_response(request, rescode):
    if request.opcode == NATPMP_OPCODE_INFO:
        response = NATPMPInfoResponse(request.version, request.opcode + 128, rescode, ['0.0.0.0'])
    else:
        response = NATPMPMappingResponse(request.version, request.opcode + 128, rescode, request.internal_port, 0, 0)
    response.sock = request.sock
    response.address = request.address
    send_response(response)


# Returns a "ok" mapping response
def send_ok_response(request, internal_port, external_port, lifetime):
    response = NATPMPMappingResponse(request.version, request.opcode + 128, NATPMP_RESULT_OK, internal_port, external_port, lifetime)
    response.sock = request.sock
    response.address = request.address
    send_response(response)


def send_denied_handshake_response(request, rescode):
    request.opcode += 128
    request.reserved = rescode
    send_response(request)

########################################################################################################################################
########################################################################################################################################
########################################################################################################################################
# Auxiliary mapping methods


# Creates a new mapping in the system
def create_mapping(ip, port, proto, client, internal_port, lifetime):
    try:
        network_management_module.add_mapping(ip, client, port, internal_port, proto.lower())
    except ValueError as exc:
        printerr("Error creating mapping %s:%d -> %s:%d %s - %s" % (ip, port, client, internal_port, proto, str(exc)))
        raise exc

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
        printlog("Updating mapping for %s:%d %s per %s request, new expiration time is %s" % (ip, port, proto, client, expiration_date.strftime("%Y-%m-%d %H:%M:%S")))
    # The mapping does not exist in the dict, create the job
    else:
        job = mapping_scheduler.add_job(remove_mapping, trigger=DateTrigger(expiration_date), args=(ip, port, proto, 'lifetime terminated'))
        CURRENT_MAPPINGS[ip][port][proto] = {'job': job, 'client': client, 'internal_port': internal_port}
        printlog("Creating %s mapping for %s:%d -> %s:%d, expiration time is %s" % (proto, ip, port, client, internal_port, expiration_date.strftime("%Y-%m-%d %H:%M:%S")))

    if settings.DEBUG:
        pprint.pprint(CURRENT_MAPPINGS)


# Removes a mapping from the system
def remove_mapping(ip, port, proto, reason):
    try:
        network_management_module.remove_mapping(ip, port, proto.lower(), CURRENT_MAPPINGS[ip][port][proto]['client'], CURRENT_MAPPINGS[ip][port][proto]['internal_port'])
    except ValueError as exc:
        printerr("Error deleting mapping with reason '%s': %s" % (reason, str(exc)))

        if reason != "lifetime terminated":
            # If it's not auto, raise it again so it can be handled at a packet-handling level
            raise exc

    del CURRENT_MAPPINGS[ip][port][proto]  # Remove the dict entry for this public IP, port and protocol

    if not CURRENT_MAPPINGS[ip][port]:
        del CURRENT_MAPPINGS[ip][port]  # If there are no more mappings for that port, remove it from the dict as well

    printlog("Removing mapping for %s:%d %s (%s)" % (ip, port, proto, reason))

    if settings.DEBUG:
        pprint.pprint(CURRENT_MAPPINGS)

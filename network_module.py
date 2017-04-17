from common_utils                           import printlog, printerr
from server_exceptions                      import MalformedPacketException
from natpmp_packets                         import NATPMPRequest
from natpmp_packets.NATPMPMappingResponse   import NATPMPMappingResponse

import socket
import settings
import select


NATPMP_PORT = 5351


def initialize_network_sockets():
    private_ips = settings.PRIVATE_INTERFACES
    sockets = []

    for ip in private_ips:
        # Iterate over the private interfaces to provide a UDP socket for each one
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind((ip, NATPMP_PORT))
            sockets.append(udp_sock)
        except Exception as err:
            printerr("Error while creating socket on %s:%d" % (ip, NATPMP_PORT))
            raise err

        printlog("Created socket on %s:%d" % (ip, NATPMP_PORT))

    from natpmp import DAEMON_START_TIME
    printlog("Daemon started at timestamp %s" % DAEMON_START_TIME)

    # Infinite network loop to attend requests
    while True:
        # Blocking call that will wait until a socket becomes available with data
        ready_sockets, _, _ = select.select(sockets, [], [])
        for sock in ready_sockets:
            data, address = sock.recvfrom(2048)
            process_received_packet(data, address, sock)


def process_received_packet(data, address, sock):
    #TODO procesar previamente el paquete seleccionanado la clase y dropeandolo si tiene opcode > 128
    try:
        request_object = NATPMPRequest.from_bytes(data)
        request_object.address = address
        request_object.sock = sock
        print(str(request_object))

        response = NATPMPMappingResponse(0, 128+request_object.opcode, 0, request_object.internal_port, request_object.external_port, 13337)
        response.sock = sock
        response.address = address
        send_response(response)
    except MalformedPacketException as e:
        printlog("Ignoring anomalous packet: " + str(e))


def send_response(response):
    response.sock.sendto(response.to_bytes(), response.address)

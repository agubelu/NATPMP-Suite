from common_utils                           import printlog, printerr
from server_exceptions                      import MalformedPacketException

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
    from natpmp_logic_common import received_bytes_to_request, process_request

    try:
        # Convert the received UDP data to a Python object representing the client request
        request = received_bytes_to_request(data)

        # Add data to the request regarding the client IP/port and the socket in which it was received
        request.address = address
        request.sock = sock

        # Send the request to be processed
        process_request(request)

    except MalformedPacketException as e:
        printlog("Ignoring anomalous packet from %s: %s" % (str(address), str(e)))


def send_response(response):
    response.sock.sendto(response.to_bytes(), response.address)


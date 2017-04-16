from common_utils           import printlog, printerr

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
    printlog("All sockets created at %s" % DAEMON_START_TIME)

    from natpmp_logic_common import process_received_packet
    # Infinite network loop to attend requests
    while True:
        # Blocking call that will wait until a socket becomes available with data
        ready_sockets, _, _ = select.select(sockets, [], [])
        for sock in ready_sockets:
            data, address = sock.recvfrom(2048)
            process_received_packet(data, address, sock)


def send_udp_response(bytedata, address, sock):
    sock.sendto(bytedata, address)

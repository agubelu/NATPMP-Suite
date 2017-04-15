from common_utils import printlog

import socket
import settings
import select
import time


def initialize_network_sockets():
    private_ips = settings.PRIVATE_INTERFACES
    udp_port = 5351
    sockets = []

    for ip in private_ips:
        # Iterate over the private interfaces to provide a UDP socket for each one
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind((ip, udp_port))
        sockets.append(udp_sock)

        printlog("Creating socket on %s:%d" % (ip, udp_port))

    from natpmp import DAEMON_START_TIME
    # Infinite network loop to attend requests
    while True:
        # Blocking call that will wait until a socket becomes available with data
        ready_sockets, _, _ = select.select(sockets, [], [])
        for sock in ready_sockets:
            data, address = sock.recvfrom(2048)
            printlog("Received '%s' from %s, %d seconds after start." % (data.decode("utf-8"), address, (time.time() - DAEMON_START_TIME)))

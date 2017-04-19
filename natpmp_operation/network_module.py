from threading                              import Thread
from time                                   import sleep

from natpmp_operation.common_utils          import printlog, printerr
from natpmp_operation.server_exceptions     import MalformedPacketException, InvalidPacketSignatureException
from natpmp_packets.NATPMPInfoResponse      import NATPMPInfoResponse
from natpmp_operation                       import security_module

import select
import socket
import settings
import traceback

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

    # Send the gratuitous multicast info at startup
    send_multicast_info()

    # Infinite network loop to attend requests
    while True:
        # Blocking call that will wait until a socket becomes available with data
        ready_sockets, _, _ = select.select(sockets, [], [])
        for sock in ready_sockets:
            data, address = sock.recvfrom(4096)
            process_received_packet(data, address, sock)


def process_received_packet(data, address, sock):
    from natpmp_operation.natpmp_logic_common import received_bytes_to_request, process_request

    try:
        # If the sender is in the TLS-enabled IPs, try to decipher the packet
        if address[0] in security_module.TLS_IPS:
            # Decipher the data and check the packet signature
            data = security_module.decipher_and_check_signature(data, security_module.ROOT_KEY, security_module[address[0]]['cert'].public_key())

        # Convert the received UDP data to a Python object representing the client request
        request = received_bytes_to_request(data)

        # Add data to the request regarding the client IP/port and the socket in which it was received
        request.address = address
        request.sock = sock

        # Send the request to be processed
        process_request(request)

    except (MalformedPacketException, InvalidPacketSignatureException) as e:
        printlog("Ignoring anomalous packet from %s: %s" % (str(address), str(e)))
        if address[0] in security_module.TLS_IPS:
            security_module.remove_ip_from_tls_enabled(address[0])
    except Exception as e:
        printerr("Uncaught exception processing a packet: %s" % str(e))
        traceback.print_exc()


def send_response(response):
    client_ip = response.address[0]

    # If the client sent the request through a secure packet, answer them the same way and remove it from the list (must handshake again)
    if client_ip in security_module.TLS_IPS:
        response_data = security_module.sign_and_cipher_data(response.to_bytes(), security_module.TLS_IPS[client_ip]['cert'].public_key(), security_module.ROOT_KEY)
        security_module.remove_ip_from_tls_enabled(client_ip)
    else:
        response_data = response.to_bytes

    response.sock.sendto(response_data, response.address)


def send_multicast_info():

    # Define the function that will carry out the work
    def work_send_multicast():

        multicast_address = '224.0.0.1'
        multicast_port = 5350

        sent = 0
        delay = 250  # Milliseconds

        # Create the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        # Send 10 requests, with the delay time doubling every time
        while sent < 10:
            if sent != 0:
                sleep(pow(2, sent - 1) * delay / 1000)

            msg = NATPMPInfoResponse(0, 128, 0, settings.PUBLIC_INTERFACES)
            sock.sendto(msg.to_bytes(), (multicast_address, multicast_port))
            sent += 1

    # Create a new thread to carry the work out
    t = Thread(target=work_send_multicast)
    t.start()

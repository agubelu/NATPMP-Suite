from common_utils           import printlog, printerr
from natpmp                 import DAEMON_START_TIME

import time


def process_received_packet(data, address, sock):

    data_str = data.decode("utf-8")
    printlog("Received '%s' from %s, %d seconds after startup." % (data_str, address, time.time() - DAEMON_START_TIME))
    printlog("From socket: %s" % sock)

    data_upper = data_str.upper()
    printlog("Sending response...")

    from network_module import send_udp_response
    send_udp_response(bytearray(data_upper, "utf-8"), address[0], sock)

from common_utils           import printlog, printerr
from natpmp                 import DAEMON_START_TIME

import time


def process_received_packet(data, address, sock):

    printlog("Received data from %s, %d seconds after startup." % (address, time.time() - DAEMON_START_TIME))
    printlog("From socket: %s" % sock)

    byte_data = bytearray(data)

    request_data = {
        'version': byte_data[0],
        'opcode': byte_data[1],
        'reserved': int.from_bytes(byte_data[2:4], byteorder='big'),
        'internal_port': int.from_bytes(byte_data[4:6], byteorder='big'),
        'external_port': int.from_bytes(byte_data[6:8], byteorder='big'),
        'requested_lifetime': int.from_bytes(byte_data[8:12], byteorder='big'),
    }

    print("Request data: " + str(request_data))

    response_bytes = bytearray()

    response_bytes += (0).to_bytes(1, 'big')
    response_bytes += (request_data["opcode"] + 128).to_bytes(1, 'big')
    response_bytes += (0).to_bytes(2, 'big')
    response_bytes += (int(time.time() - DAEMON_START_TIME)).to_bytes(4, 'big')
    response_bytes += (request_data["internal_port"]).to_bytes(2, 'big')
    response_bytes += (request_data["external_port"]).to_bytes(2, 'big')
    response_bytes += (request_data["requested_lifetime"]).to_bytes(4, 'big')

    response_data = {
        'version': response_bytes[0],
        'opcode': response_bytes[1],
        'result': int.from_bytes(response_bytes[2:4], byteorder='big'),
        'seconds_since_restart': int.from_bytes(response_bytes[4:8], byteorder='big'),
        'internal_port': int.from_bytes(response_bytes[8:10], byteorder='big'),
        'external_port': int.from_bytes(response_bytes[10:12], byteorder='big'),
        'assigned_lifetime': int.from_bytes(response_bytes[12:16], byteorder='big'),
    }

    print("Response data: " + str(response_data))

    from network_module import send_udp_response
    send_udp_response(response_bytes, address, sock)

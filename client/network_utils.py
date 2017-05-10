import netifaces
import sys
import socket
import select


NATPMP_PORT = 5351


def get_default_router_address():
    gateways = netifaces.gateways()
    if not gateways or 'default' not in gateways or netifaces.AF_INET not in gateways['default']:
        raise IOError("Default gateway address could not be found, please specify it manually using the -g flag.")
    else:
        return gateways['default'][netifaces.AF_INET][0]


def send_and_receive_with_timeout(sock, dst_ip, data, timeout):
    # Sock is already initialized and bound, data is already bytes
    sock.sendto(data, (dst_ip, NATPMP_PORT))
    ready_socks, _, _ = select.select([sock], [], [], timeout / 1000)  # Timeout in millis

    if ready_socks:
        ready_socket = ready_socks[0]
        return ready_socket.recvfrom(65535)
    else:
        return None, None


# Sends a request to the server and grabs the response
# It waits an initial delay of 500ms and then doubles for every failed request
# until it waits 64 s and then gives up.

# Raises ConnectionRefusedError if the destination port is not available.
def send_request_get_response(dst_ip, data, raw=False, frame=None, max_retries=8):
    # Create the socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setblocking(0)
    udp_sock.connect((dst_ip, NATPMP_PORT))

    initial_delay = 500  # Milliseconds
    retries = 0

    byte_data = data if raw else data.to_bytes()

    while True:
        data_response, address_response = send_and_receive_with_timeout(udp_sock, dst_ip, byte_data, initial_delay * pow(2, retries))

        if address_response is not None and address_response[0] != dst_ip:
            # The response was sent by someone different than the router, try again
            continue

        if data_response:
            return data_response

        retries += 1

        if frame:
            frame.insert_info_line("Router did not reply, trying again...")
        else:
            print("Router did not reply, trying again...")

        if retries == max_retries:
            break

    return None

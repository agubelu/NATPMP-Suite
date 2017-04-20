from client.command_processor   import process_command_line_params
from client                     import normalized_request
from client.network_utils       import send_request_get_response

import sys


if __name__ == "__main__":

    if "gui" in sys.argv:
        pass # TODO launch the client GUI
    else:
        # Get the namespace from the command line
        namespace = process_command_line_params()

        # Normalize the namespace into a common object for both the command line and the GUI
        req_norm = normalized_request.from_namespace(namespace)
        resp = send_request_get_response(req_norm.router_addr, req_norm.to_request_object())

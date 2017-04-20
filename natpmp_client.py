from client.command_processor   import process_command_line_params
from client                     import normalized_request

import sys


if __name__ == "__main__":

    if "gui" in sys.argv:
        pass # TODO launch the client GUI
    else:
        # Get the namespace from the command line
        namespace = process_command_line_params()

        # Normalize the namespace into a common object for both the command line and the GUI
        req_norm = normalized_request.from_namespace(namespace)
        print(str(req_norm))

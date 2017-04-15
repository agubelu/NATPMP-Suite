from config_module      import process_command_line_params
from network_module     import initialize_network_sockets

import time


if __name__ == "__main__":
    # Initialize the current time to populate the "seconds since boot" parameter for the responses
    DAEMON_START_TIME = time.time()

    # Process the command-line parameters
    process_command_line_params()

    # Start the UDP sockets to listen for requests from the clients
    initialize_network_sockets()

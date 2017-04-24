#!/usr/bin/env python3

import time

from natpmp_operation                   import security_module
from natpmp_operation.network_module    import initialize_network_sockets

from natpmp_operation.config_module     import process_command_line_params

# Initialize the current time to populate the "seconds since boot" parameter for the responses
DAEMON_START_TIME = time.time()

if __name__ == "__main__":

    # Process the command-line parameters
    process_command_line_params()

    import settings
    if settings.ALLOW_TLS_IN_V1:
        security_module.initialize_root_certificate()

    # Start the UDP sockets to listen for requests from the clients
    initialize_network_sockets()

#!/usr/bin/env python3

import time
import signal
import sys

from natpmp_operation                           import security_module
from natpmp_operation.network_module            import initialize_network_sockets
from natpmp_operation.config_module             import process_command_line_params
from natpmp_operation.network_management_module import init_tables, flush_tables
from natpmp_operation.common_utils              import printlog

# Initialize the current time to populate the "seconds since boot" parameter for the responses
DAEMON_START_TIME = time.time()

if __name__ == "__main__":

    # Process the command-line parameters
    process_command_line_params()

    import settings
    if settings.ALLOW_TLS_IN_V1:
        security_module.initialize_root_certificate()

    # Init nft tables
    init_tables()

    # Set the SIGTERM handler, to flush the NAT-PMP table if the daemon is terminated
    def handle_sigterm(signal, frame):
        printlog("Daemon terminating, flushing NAT-PMP status in nftables...")
        flush_tables()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)

    # Start the UDP sockets to listen for requests from the clients in an infinite loop
    try:
        initialize_network_sockets()
    except KeyboardInterrupt:
        handle_sigterm(None, None)

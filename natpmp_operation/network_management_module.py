from subprocess                     import call
from natpmp_operation.common_utils  import printlog

import sys


def init_tables():
    create_tables()
    flush_tables()
    printlog("Table 'natpmp' initialized on nftables.")


def create_tables():
    init_table_command = "nft add table ip natpmp"
    init_table_status = call(init_table_command.split())
    if init_table_status:
        sys.exit("Command '%s' returned non-zero error code (%d)" % (init_table_command, init_table_status))


def flush_tables():
    flush_table_command = "nft flush table ip natpmp"
    flush_table_status = call(flush_table_command.split())
    if flush_table_status:
        sys.exit("Command '%s' returned non-zero error code (%d)" % (flush_table_command, flush_table_status))
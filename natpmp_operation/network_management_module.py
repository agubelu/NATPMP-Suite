from subprocess                     import call
from natpmp_operation.common_utils  import printlog, is_valid_ip_string

import sys
import netifaces


NATPMP_TABLE_NAME = "natpmp"
INTERFACE_NAMES = {}


def init_tables():
    create_tables()
    flush_tables()
    exec_or_die("nft add chain %s prerouting { type nat hook prerouting priority 0 ; }" % NATPMP_TABLE_NAME)
    exec_or_die("nft add chain %s postrouting { type nat hook postrouting priority 100 ; }" % NATPMP_TABLE_NAME)

    printlog("Table 'natpmp' initialized on nftables.")


def create_tables():
    exec_or_die("nft add table ip %s" % NATPMP_TABLE_NAME)


def flush_tables():
    exec_or_die("nft flush table ip %s" % NATPMP_TABLE_NAME)


def add_mapping(public_ip, private_ip, public_port, private_port, proto):
    if proto not in ["tcp", "udp"]:
        raise ValueError("Proto '%s' is not valid" % proto)

    if not is_valid_ip_string(public_ip):
        raise ValueError("Public IP address '%s' is not valid" % public_ip)

    if not is_valid_ip_string(private_ip):
        raise ValueError("Private IP address '%s' is not valid" % private_ip)

    iface_name = get_interface_name(public_ip)
    if not iface_name:
        raise ValueError("No interface found for public address " + public_ip)

    command = "nft add rule %s prerouting iif %s %s dport %d dnat %s:%d" % (NATPMP_TABLE_NAME, iface_name, proto, public_port, private_ip, private_port)

    # We've come so far to die here now
    exec_or_die(command, soft=True)

########################################################################################################################


def exec_or_die(command, soft=False):
    status = call(command.split())
    if status:
        if soft:
            raise ValueError("Command '%s' returned non-zero error code (%d)" % (command, status))
        else:
            sys.exit("Command '%s' returned non-zero error code (%d)" % (command, status))


def get_interface_name(public_address):

    if public_address in INTERFACE_NAMES:
        return INTERFACE_NAMES[public_address]

    ifaces = netifaces.interfaces()
    for iface_name in ifaces:
        for iface_data in netifaces.ifaddresses(iface_name)[netifaces.AF_INET]:
            if "addr" in iface_data and iface_data["addr"] == public_address:
                INTERFACE_NAMES[public_address] = iface_name
                return iface_name

    return False

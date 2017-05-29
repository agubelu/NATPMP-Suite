from subprocess                     import call, check_output, CalledProcessError
from natpmp_operation.common_utils  import printlog, is_valid_ip_string

import sys
import netifaces
import re


NATPMP_TABLE_NAME = "natpmp"
INTERFACE_NAMES = {}


def init_tables():
    create_tables()
    flush_tables()
    exec_or_die("nft add chain %s prerouting { type nat hook prerouting priority 0 ; }" % NATPMP_TABLE_NAME)
    exec_or_die("nft add chain %s postrouting { type nat hook postrouting priority 100 ; }" % NATPMP_TABLE_NAME)

    printlog("Table '%s' initialized on nftables." % NATPMP_TABLE_NAME)


def create_tables():
    exec_or_die("nft add table ip %s" % NATPMP_TABLE_NAME)


def flush_tables():
    exec_or_die("nft flush table ip %s" % NATPMP_TABLE_NAME)


def add_mapping(public_ip, private_ip, public_port, private_port, proto):
    check_mapping_params(proto, public_ip, private_ip)
    iface_name = get_interface_name(public_ip)

    command1 = "nft add rule %s prerouting iif %s %s dport %d dnat %s:%d" % (NATPMP_TABLE_NAME, iface_name, proto, public_port, private_ip, private_port)
    command2 = "nft add rule %s postrouting ip daddr %s %s dport %d masquerade" % (NATPMP_TABLE_NAME, private_ip, proto, private_port)
    # We've come so far to die here now
    exec_or_die(command1, soft=True)
    exec_or_die(command2, soft=True)


def remove_mapping(public_ip, public_port, proto):
    check_mapping_params(proto, public_ip)
    iface_name = get_interface_name(public_ip)

    # Get the handle for the rule
    list_command = "nft list table %s -a -nnn" % NATPMP_TABLE_NAME

    try:
        list_output = check_output(list_command.split())
    except CalledProcessError as e:
        raise ValueError("Command %s returned non-zero error code (%d)" % (list_command, e.returncode))

    regex = "iif %s %s dport %d.*# handle (\d*)" % (iface_name, proto, public_port)

    for list_entry in list_output.splitlines():
        entry_stripped = list_entry.decode("utf-8").strip()
        match = re.search(regex, entry_stripped)

        if match:
            handle = match.group(1)
            remove_command = "nft delete rule %s prerouting handle %s" % (NATPMP_TABLE_NAME, handle)
            exec_or_die(remove_command, soft=True)
            return

    # No rule matched
    raise ValueError("Mapping removal for %s:%d %s failed: no such mapping" % (public_ip, public_port, proto))

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


def check_mapping_params(proto=None, public_ip=None, private_ip=None):

    if proto:
        if proto not in ["tcp", "udp"]:
            raise ValueError("Proto '%s' is not valid" % proto)

    if public_ip:
        if not is_valid_ip_string(public_ip):
            raise ValueError("Public IP address '%s' is not valid" % public_ip)

        if not get_interface_name(public_ip):
            raise ValueError("No interface found for public address " + public_ip)

    if private_ip:
        if not is_valid_ip_string(private_ip):
            raise ValueError("Private IP address '%s' is not valid" % private_ip)

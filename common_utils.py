from IPy import IP
import ipaddress
import sys


# Prints a string to the stderr output with a trailing newline.
def printerr(string):
    sys.stderr.write(string + "\n")


# Returns True if the parameter is a String and represents a valid IPv4 address, False otherwise.
def is_valid_ip_string(param):
    if type(param) is not str:
        return False
    try:
        ipaddress.ip_address(param)
        return True
    except ValueError:
        return False


# Returns True if the parameter represents a private IPv4 address, True if it's public, and raises ValueError if it's not a valid address.
def check_ip_address_type(param, type):
    if not is_valid_ip_string(param):
        raise ValueError

    return IP(param).iptype() == type

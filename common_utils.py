from IPy        import IP
from datetime   import datetime, timedelta

import ipaddress
import sys


# Prints a string to the standard output, adding a timestamp for logging purposes
def printlog(string):
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("[%s] %s" % (time_str, string))


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
def check_ip_address_type(param, iptype):
    if not is_valid_ip_string(param):
        raise ValueError

    return IP(param).iptype() == iptype


# Returns a future date object, ahead by the current time as specified in seconds
def get_future_date(seconds):
    return datetime.now() + timedelta(seconds=seconds)

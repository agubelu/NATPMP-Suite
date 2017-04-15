import ipaddress

# Returns True if the parameter is a String and represents a valid IP address, False otherwise.
def is_valid_ip_string(param):
    if type(param) is not str:
        return False

    try:
        ipaddress.ip_address(param)
        return True
    except ValueError:
        return False
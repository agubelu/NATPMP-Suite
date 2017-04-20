import netifaces
import sys


def get_default_router_address():
    gateways = netifaces.gateways()
    if not gateways or 'default' not in gateways or netifaces.AF_INET not in gateways['default']:
        sys.exit("Default gateway address could not be found, please specify it manually using the -g flag.")
    else:
        return gateways['default'][netifaces.AF_INET][0]

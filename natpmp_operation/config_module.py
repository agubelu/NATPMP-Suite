import argparse
import sys

import settings
from natpmp_operation.common_utils                  import is_valid_ip_string, printerr, check_ip_address_type
from natpmp_operation.network_management_module     import get_interface_name


def process_command_line_params():
    # Get the parameters and their values from the command line
    namespace = get_params_namespace()

    # Place those values into the settings file for global access
    push_namespace_to_settings(namespace)

    # Check that the values in the settings are valid, raising errors or warnings if they are not
    assert_settings_ok()


def get_params_namespace():

    # Use the argument parser from Python 3.5 stdlib and return the corresponding namespace
    parser = argparse.ArgumentParser(description="A NAT-PMP daemon with some substantial enhancements to the base protocol.")

    parser.add_argument('--use-settings-file', '-file', action='store_true',
                        help="Uses the settings.py file to configure the daemon, all other parameters will be ignored.")

    parser.add_argument('--private-interfaces', '-p', nargs='+', help="Private interfaces to listen for requests.",
                        metavar="ip_address")
    parser.add_argument('--public-interfaces', '-u', nargs='+',
                        help="Public interfaces available for mappings. When using NAT-PMP v0, only the first one will be used.",
                        metavar="ip_address")

    parser.add_argument('--version0', '-v0', action='store_true', help="Allow usage of the NAT-PMP version 0")
    parser.add_argument('--version1', '-v1', action='store_true', help="Allow usage of the NAT-PMP version 1")

    parser.add_argument('--allow-security', '-sec', action='store_true',
                        help="Allow secure requests when using NAT-PMP version 1")
    parser.add_argument('--force-security', '-fsec', action='store_true',
                        help="Denies non-secure requests when using NAT-PMP version 1")
    parser.add_argument('--strict-certs', '-s', action='store_true',
                        help="Only accept certificates issued by the daemon")

    parser.add_argument('--min-port', '-minp', nargs='?',
                        help="Minimum external port number available for mappings (inclusive). Defaults to 1.",
                        metavar="port", type=int, default=1)

    parser.add_argument('--max-port', '-maxp', nargs='?',
                        help="Maximum external port number available for mappings (inclusive). Defaults to 65535.",
                        metavar="port", type=int, default=65535)

    parser.add_argument('--excluded-ports', '-x', nargs='+', help="Ports to exclude from mapping requests.",
                        metavar="port", type=int)

    parser.add_argument('--min-lifetime', '-minl', nargs='?',
                        help="Minimum lifetime for port mappings, in seconds. Defaults to 60 (1 minute).",
                        metavar="seconds", type=int, default=60)

    parser.add_argument('--max-lifetime', '-maxl', nargs='?',
                        help="Maximum lifetime for port mappings, in seconds. Defaults to 3600 (1 hour).",
                        metavar="seconds", type=int, default=3600)

    parser.add_argument('--fixed-lifetime', '-fixedl', nargs='?',
                        help="Fixed lifetime in seconds for all mappings. Overrides --max-lifetime and --min-lifetime.",
                        metavar="seconds", type=int, default=None)

    parser.add_argument('--blacklist', '-b', action='store_true',
                        help="Run in blacklist mode, deny requests from the blacklisted addresses.")

    parser.add_argument('--blacklisted-addresses', '-bl', nargs='+', help="Addresses to deny requests from.",
                        metavar="ip_address")

    parser.add_argument('--whitelist', '-w', action='store_true',
                        help="Run in whitelist mode, only accept requests from the whitelisted addresses.")

    parser.add_argument('--whitelisted-addresses', '-wl', nargs='+', help="Addresses to accept requests from.",
                        metavar="ip_address")

    parser.add_argument('-web', nargs=2, help="Enable the administrative web interface. Set the password to an empty string to disable it.",
                        metavar=("port", "password"))

    parser.add_argument('-debug', action='store_true',
                        help="Print the current state of all mappings after every request and log web interface access.")

    return parser.parse_args()


def push_namespace_to_settings(namespace):

    # If the user requested to use the settings file as-is, don't push the command-line values into it.
    if namespace.use_settings_file:
        return

    settings.PRIVATE_INTERFACES = namespace.private_interfaces
    settings.PUBLIC_INTERFACES = namespace.public_interfaces
    settings.ALLOW_VERSION_0 = namespace.version0
    settings.ALLOW_VERSION_1 = namespace.version1
    settings.ALLOW_SECURITY_IN_V1 = namespace.allow_security
    settings.FORCE_SECURITY_IN_V1 = namespace.force_security
    settings.STRICT_CERTIFICATE_CHECKING = namespace.strict_certs
    settings.MIN_ALLOWED_MAPPABLE_PORT = namespace.min_port
    settings.MAX_ALLOWED_MAPPABLE_PORT = namespace.max_port
    settings.EXCLUDED_PORTS = namespace.excluded_ports
    settings.MIN_ALLOWED_LIFETIME = namespace.min_lifetime
    settings.MAX_ALLOWED_LIFETIME = namespace.max_lifetime
    settings.FIXED_LIFETIME = namespace.fixed_lifetime
    settings.BLACKLIST_MODE = namespace.blacklist
    settings.BLACKLISTED_IPS = namespace.blacklisted_addresses
    settings.WHITELIST_MODE = namespace.whitelist
    settings.WHITELISTED_IPS = namespace.whitelisted_addresses
    settings.DEBUG = namespace.debug

    if namespace.web:
        settings.ALLOW_WEB_INTERFACE = True
        settings.WEB_INTERFACE_PORT = namespace.web[0]
        settings.WEB_INTERFACE_PASSWORD = namespace.web[1]
    else:
        settings.ALLOW_WEB_INTERFACE = False


def assert_settings_ok():

    # Check that there is at least 1 private interface
    if settings.PRIVATE_INTERFACES is None or len(settings.PRIVATE_INTERFACES) < 1:
        sys.exit("Error: must specify at least 1 private interface to listen for requests.")

    # Check that the private interfaces are all valid IP addresses
    _check_all_ips_correct(settings.PRIVATE_INTERFACES, "private interfaces")

    # Check that the private interfaces are private IP addresses, raise a warning otherwise
    for ip in settings.PRIVATE_INTERFACES:
        try:
            if not check_ip_address_type(ip, "PRIVATE"):
                printerr("Warning: IP address '%s' from the private interfaces is not a private IP address. Proceed with caution." % ip)
        except ValueError:
            pass

    # Check that there is at least 1 public interface
    if settings.PUBLIC_INTERFACES is None or len(settings.PUBLIC_INTERFACES) < 1:
        sys.exit("Error: must specify at least 1 public interface to map ports into.")

    # Check that the public interfaces are all valid IP addresses
    _check_all_ips_correct(settings.PUBLIC_INTERFACES, "public interfaces")

    # Check that the public interfaces are public IP addresses, raise a warning otherwise
    for ip in settings.PUBLIC_INTERFACES:
        try:
            if not get_interface_name(ip):
                sys.exit("Error: Public IP address '%s' could not be found in any interface." % ip)
            if not check_ip_address_type(ip, "PUBLIC"):
                printerr("Warning: IP address '%s' from the public interfaces is not a public IP address. Proceed with caution." % ip)
        except ValueError:
            pass

    # Check that at least one of the versions of the protocol is enabled
    if not settings.ALLOW_VERSION_0 and not settings.ALLOW_VERSION_1:
        sys.exit("Error: must allow at least one version of the protocol (either 0, 1 or both).")

    # Raise a warning if TLS is enabled but version 1 isn't
    if settings.ALLOW_SECURITY_IN_V1 and not settings.ALLOW_VERSION_1:
        printerr("Warning: TLS in version 1 is enabled but version 1 itself is not. This configuration parameter will have no effect.")

    # Raise a warning if TLS is forced but version 1 isn't
    if settings.FORCE_SECURITY_IN_V1 and not settings.ALLOW_VERSION_1:
        printerr("Warning: TLS in version 1 is forced but version 1 itself is not. This configuration parameter will have no effect.")

    # Raise a warning if TLS is forced but TLS is not enabled
    if settings.FORCE_SECURITY_IN_V1 and not settings.ALLOW_SECURITY_IN_V1:
        sys.exit("Error: Force TLS is enabled but TLS itself is not. Clients will not be able to issue requests for V1.")

    # Raise a warning if strict certs are enabled but version 1 isn't
    if settings.STRICT_CERTIFICATE_CHECKING and not settings.ALLOW_VERSION_1:
        printerr("Warning: Strict certificate checking is enabled but version 1 itself is not. This configuration parameter will have no effect.")

    # Raise a warning if strict certs are enabled but TLS isn't
    if settings.STRICT_CERTIFICATE_CHECKING and not settings.ALLOW_SECURITY_IN_V1:
        printerr("Warning: Strict certificate checking is enabled but version TLS itself is not. This configuration parameter will have no effect.")

    # Raise a warning if the minimum allowed port is less than 1
    if settings.MIN_ALLOWED_MAPPABLE_PORT < 1:
        printerr("Warning: Minimum mappable port is less than 1. This will have no special effect other than being the same as setting it to 1.")

    # Raise a warning if the maximum allowed port is greater than 65535
    if settings.MAX_ALLOWED_MAPPABLE_PORT > 65535:
        printerr("Warning: Maximum mappable port is greater than 65535. This will have no special effect other than being the same as setting it to 65535.")

    # Check that the minimum mappable port is not greater than the maximum
    if settings.MIN_ALLOWED_MAPPABLE_PORT > settings.MAX_ALLOWED_MAPPABLE_PORT:
        sys.exit("Error: The minimum mappable port cannot be greater than the maximum one.")

    # Check that the minimum allowed lifetime is a positive number
    if settings.MIN_ALLOWED_LIFETIME <= 0:
        sys.exit("Error: The minimum allowed lifetime must be a positive integer.")

    # Check that the maximum allowed lifetime is a positive number
    if settings.MAX_ALLOWED_LIFETIME <= 0:
        sys.exit("Error: The maximum allowed lifetime must be a positive integer.")

    # Check that the minimum allowed lifetime is not greater than the maximum
    if settings.MIN_ALLOWED_LIFETIME > settings.MAX_ALLOWED_LIFETIME:
        sys.exit("Error: The minimum allowed lifetime cannot be greater than the maximum.")

    # Check that, if it's set, the fixed lifetime is a positive integer:
    if settings.FIXED_LIFETIME is not None and settings.FIXED_LIFETIME <= 0:
        sys.exit("Error: The fixed lifetime amount must be a positive integer.")

    # Check that the blacklist and whitelist mode are not active at the same time
    if settings.BLACKLIST_MODE and settings.WHITELIST_MODE:
        sys.exit("Error: cannot operate under both the whitelist and the blacklist mode at the same time.")

    # If we are operating under blacklist mode, check that it's set and all IP addresses are correct
    if settings.BLACKLIST_MODE:
        if settings.BLACKLISTED_IPS is None or len(settings.BLACKLISTED_IPS) == 0:
            printerr("Warning: Blacklist mode is activated but the blacklist is empty. This will result in accepting all requests from any client.")
        else:
            _check_all_ips_correct(settings.BLACKLISTED_IPS, "the blacklist")

    # If we are operating under whitelist mode, check that it's set and all IP addresses are correct
    if settings.WHITELIST_MODE:
        if settings.WHITELISTED_IPS is None or len(settings.WHITELISTED_IPS) == 0:
            printerr("Warning: Whitelist mode is activated but the whitelist is empty. This will result in denying all requests from every client.")
        else:
            _check_all_ips_correct(settings.WHITELISTED_IPS, "the whitelist")

    if settings.ALLOW_WEB_INTERFACE:
        try:
            port_int = int(settings.WEB_INTERFACE_PORT)
            if not 1 <= port_int <= 65535:
                raise ValueError
        except ValueError:
            sys.exit("The web port must be an integer between 1 and 65535.")

        if not settings.WEB_INTERFACE_PASSWORD:
            printerr("Warning: the administrative website is online without a password.")

########################################################################################################################
########################################################################################################################
########################################################################################################################


def _check_all_ips_correct(ip_list, name):
    for ip in ip_list:
        if not is_valid_ip_string(ip):
            printerr("Warning: IP address '%s' from %s is not a valid IPv4 address." % (ip, name))

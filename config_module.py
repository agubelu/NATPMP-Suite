from common_utils import is_valid_ip_string, printerr

import settings
import argparse
import sys


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

    parser.add_argument('--use-settings-file', '-f', action='store_true',
                        help="Uses the settings.py file to configure the daemon, all other parameters will be ignored.")

    parser.add_argument('--private-interfaces', '-p', nargs='+', help="Private interfaces to listen for requests.",
                        metavar="ip_address")
    parser.add_argument('--public-interfaces', '-u', nargs='+',
                        help="Public interfaces available for mappings. When using NAT-PMP v0, only the first one will be used.",
                        metavar="ip_address")

    parser.add_argument('--version0', '-v0', action='store_true', help="Allow usage of the NAT-PMP version 0")
    parser.add_argument('--version1', '-v1', action='store_true', help="Allow usage of the NAT-PMP version 1")

    parser.add_argument('--allow-tls', '-tls', action='store_true',
                        help="Allow TLS and security functions when using NAT-PMP version 1")
    parser.add_argument('--force-tls', '-ftls', action='store_true',
                        help="Denies non-TLS requests when using NAT-PMP version 1")
    parser.add_argument('--strict-certs', '-s', action='store_true',
                        help="Only accept certificates issued by the daemon")

    parser.add_argument('--min-port', '-minp', nargs=1,
                        help="Minimum external port number available for mappings (inclusive). Defaults to 1.",
                        metavar="port", type=int, default=1)

    parser.add_argument('--max-port', '-maxp', nargs=1,
                        help="Maximum external port number available for mappings (inclusive). Defaults to 65535.",
                        metavar="port", type=int, default=65535)

    parser.add_argument('--min-lifetime', '-minl', nargs=1,
                        help="Minimum lifetime for port mappings, in seconds. Defaults to 60 (1 minute).",
                        metavar="seconds", type=int, default=60)

    parser.add_argument('--max-lifetime', '-maxl', nargs=1,
                        help="Maximum lifetime for port mappings, in seconds. Defaults to 3600 (1 hour).",
                        metavar="seconds", type=int, default=3600)

    parser.add_argument('--fixed-lifetime', '-fixedl', nargs=1,
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

    return parser.parse_args()


def push_namespace_to_settings(namespace):

    # If the user requested to use the settings file as-is, don't push the command-line values into it.
    if namespace.use_settings_file:
        return

    settings.PRIVATE_INTERFACES = namespace.private_interfaces
    settings.PUBLIC_INTERFACES = namespace.public_interfaces
    settings.ALLOW_VERSION_0 = namespace.version0
    settings.ALLOW_VERSION_1 = namespace.version1
    settings.ALLOW_TLS_IN_V1 = namespace.allow_tls
    settings.FORCE_TLS_IN_V1 = namespace.force_tls
    settings.STRICT_CERTIFICATE_CHECKING = namespace.strict_certs
    settings.MIN_ALLOWED_MAPPABLE_PORT = namespace.min_port
    settings.MAX_ALLOWED_MAPPABLE_PORT = namespace.max_port
    settings.MIN_ALLOWED_LIFETIME = namespace.min_lifetime
    settings.MAX_ALLOWED_LIFETIME = namespace.max_lifetime
    settings.FIXED_LIFETIME = namespace.fixed_lifetime
    settings.BLACKLIST_MODE = namespace.blacklist
    settings.BLACKLISTED_IPS = namespace.blacklisted_addresses
    settings.WHITELIST_MODE = namespace.whitelist
    settings.WHITELISTED_IPS = namespace.whitelisted_addresses


def assert_settings_ok():

    # Check that there is at least 1 private interface
    if settings.PRIVATE_INTERFACES is None or len(settings.PRIVATE_INTERFACES) < 1:
        sys.exit("Error: must specify at least 1 private interface to listen for requests.")

    # Check that the private interfaces are all valid IP addresses
    _check_all_ips_correct(settings.PRIVATE_INTERFACES, "private interfaces")

    # Check that there is at least 1 public interface
    if settings.PUBLIC_INTERFACES is None or len(settings.PUBLIC_INTERFACES) < 1:
        sys.exit("Error: must specify at least 1 public interface to map ports into.")

    # Check that the public interfaces are all valid IP addresses
    _check_all_ips_correct(settings.PUBLIC_INTERFACES, "public interfaces")

    # Check that at least one of the versions of the protocol is enabled
    if not settings.ALLOW_VERSION_0 and not settings.ALLOW_VERSION_1:
        sys.exit("Error: must allow at least one version of the protocol (either 0, 1 or both).")

    # Raise a warning if TLS is enabled but version 1 isn't
    if settings.ALLOW_TLS_IN_V1 and not settings.ALLOW_VERSION_1:
        printerr("Warning: TLS in version 1 is enabled but version 1 itself is not. This configuration parameter will have no effect.")

    # Raise a warning if TLS is forced but version 1 isn't
    if settings.FORCE_TLS_IN_V1 and not settings.ALLOW_VERSION_1:
        printerr("Warning: TLS in version 1 is forced but version 1 itself is not. This configuration parameter will have no effect.")

    # Raise a warning if TLS is forced but TLS is not enabled
    if settings.FORCE_TLS_IN_V1 and not settings.ALLOW_TLS_IN_V1:
        printerr("Warning: Force TLS is enabled but TLS itself is not. This configuration parameter will have no effect.")


########################################################################################################################
########################################################################################################################
########################################################################################################################


def _check_all_ips_correct(list, name):
    for ip in list:
        if not is_valid_ip_string(ip):
            printerr("Warning: IP address '%s' from %s is not a valid IPv4 address." % (ip, name))
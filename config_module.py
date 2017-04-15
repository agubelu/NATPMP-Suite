import settings
import argparse


def process_command_line_params():
    parser = argparse.ArgumentParser(
        description="A NAT-PMP daemon with some substantial enhancements to the base protocol.")

    parser.add_argument('--use-settings-file', '-f', action='store_true', help="Uses the settings.py file to configure the daemon, all other parameters will be ignored.")

    parser.add_argument('--private-interfaces', '-p', nargs='+', help="Private interfaces to listen for requests.",
                        metavar="ip_address")
    parser.add_argument('--public-interfaces', '-u', nargs='+',
                        help="Public interfaces available for mappings. When using NAT-PMP v0, only the first one will be used.",
                        metavar="ip_address")

    parser.add_argument('--version0', '-v0', action='store_true', help="Allow usage of the NAT-PMP version 0")
    parser.add_argument('--version1', '-v1', action='store_true', help="Allow usage of the NAT-PMP version 1")

    parser.add_argument('--allow-tls', '-tls', action='store_true', help="Allow TLS and security functions when using NAT-PMP version 1")
    parser.add_argument('--force-tls', '-ftls', action='store_true', help="Denies non-TLS requests when using NAT-PMP version 1")
    parser.add_argument('--strict-certs', '-s', action='store_true', help="Only accept certificates issued by the daemon")

    parser.add_argument('--min-port', '-minp', nargs=1,
                        help="Minimum external port number available for mappings (inclusive).",
                        metavar="port", type=int, default=1)

    parser.add_argument('--max-port', '-maxp', nargs=1,
                        help="Maximum external port number available for mappings (inclusive).",
                        metavar="port", type=int, default=65535)

    parser.add_argument('--min-lifetime', '-minl', nargs=1,
                        help="Minimum lifetime for port mappings, in seconds.",
                        metavar="seconds", type=int, default=60)

    parser.add_argument('--max-lifetime', '-maxl', nargs=1,
                        help="Maximum lifetime for port mappings, in seconds.",
                        metavar="seconds", type=int, default=60)

    parser.add_argument('--fixed-lifetime', '-fixedl', nargs=1,
                        help="Fixed lifetime in seconds for all mappings. Overrides --max-lifetime and --min-lifetime.",
                        metavar="seconds", type=int, default=None)

    parser.add_argument('--blacklist', '-b', action='store_true',
                        help="Run in blacklist mode, deny requests from the blacklisted addresses.")

    parser.add_argument('--blacklisted-addresses', '-bl', nargs='+', help="Addresses to deny requests from.",
                        metavar="ip_address")

    parser.add_argument('--whitelist', '-w', action='store_true',
                        help="Run in whitelist mode, only accept requests from the whitelisted addresses.")

    parser.add_argument('--whitelist-addresses', '-wl', nargs='+', help="Addresses to accept requests from.",
                        metavar="ip_address")

    namespace = parser.parse_args()

    print(namespace)

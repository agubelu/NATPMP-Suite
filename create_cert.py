# Utility for creating certificates for clients, signed with the root key.

from natpmp_operation                           import security_module
from natpmp_operation.common_utils              import is_valid_ip_string

from cryptography                               import x509
from cryptography.hazmat.backends               import default_backend
from cryptography.hazmat.primitives             import serialization, hashes
from cryptography.hazmat.primitives.asymmetric  import rsa
from cryptography.x509.oid                      import NameOID

from datetime                                   import datetime, timedelta
from getpass                                    import getpass

import sys
import os


def create_cert(ip, seconds, der):
    security_module.initialize_root_certificate()

    client_cert_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "certs/%s.crt" % ip)
    client_key_path = os.path.join(os.path.dirname(client_cert_path), "%s.key" % ip)

    # Ask the user for a password for the private key
    while True:
        print("Please enter a password for the certificate private key (leave blank for no password)", flush=True)
        pass1 = getpass()
        print("Please repeat the password", flush=True)
        pass2 = getpass()

        if pass1 == pass2:
            break
        else:
            print("Passwords do not match, please try again\n")

    # Create the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate the certificate, signed with our root private key
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ACME"),
        x509.NameAttribute(NameOID.COMMON_NAME, ip),
    ])

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ACME"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"NAT-PMP Daemon"),
    ])

    client_cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(seconds=seconds)) \
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(ip)]),
            critical=False,
        ) \
        .sign(security_module.ROOT_KEY, hashes.SHA256(), default_backend())

    key_encr_algo = serialization.BestAvailableEncryption(bytes(pass1, "utf-8")) if len(pass1) > 0 else serialization.NoEncryption()
    encoding = serialization.Encoding.DER if der else serialization.Encoding.PEM

    # Save the private key with 600 permissions
    with open(client_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=key_encr_algo
        ))

    os.chmod(client_key_path, 0o600)

    # Save the certificate with 644 permissions
    with open(client_cert_path, "wb") as f:
        f.write(client_cert.public_bytes(encoding))

    os.chmod(client_cert_path, 0o644)

    print("Certificate and key for %s stored in %s" % (ip, os.path.dirname(client_cert_path)))

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or '-h' in args or '--help' in args:
        print("""
Usage: create-cert.py client_ip lifetime [-der]

    client_ip: The IPv4 address that will be used as the 'subject' for the certificate.
    lifetime: Lifetime for the certificate in seconds, starting when it's created.

    If -der is provided, will generate a certificate in the DER binary format, instead of the regular PEM.
""")
        sys.exit(0)

    if len(args) < 2:
        sys.exit("Not enough arguments, use create-cert.py --help to get help.")

    client_ip = args[0]
    lifetime = args[1]

    # Check that the IP is OK
    if not is_valid_ip_string(client_ip):
        sys.exit("The client IP address is not a valid IP.")

    # Check that the lifetime is OK
    try:
        lifetime_int = int(lifetime)
        if lifetime_int <= 0:
            raise ValueError
    except ValueError:
        sys.exit("The lifetime must be a positive integer.")

    # Everything is fine, create the cert
    create_cert(client_ip, lifetime_int, '-der' in args)

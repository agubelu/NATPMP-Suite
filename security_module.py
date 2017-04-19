from common_utils                                   import printlog
from getpass                                        import getpass
from datetime                                       import datetime, timedelta

from cryptography                                   import x509
from cryptography.x509.oid                          import NameOID
from cryptography.hazmat.backends                   import default_backend
from cryptography.hazmat.primitives                 import serialization, hashes
from cryptography.hazmat.primitives.asymmetric      import rsa
from cryptography.hazmat.primitives.serialization   import load_pem_private_key

import os


ROOT_CERTIFICATE = None
ROOT_KEY = None


# Loads the system root, self-signed cert into the module, creating it if it doesn't exist yet
def initialize_root_certificate():

    root_cert_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "certs/root.crt")
    root_pk_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "certs/root.key")

    if not os.path.exists(root_cert_path) or not os.path.exists(root_pk_path):
        # Must create a new cert-key pair
        printlog("Root certificate and/or private key not found, creating new ones...")

        # Ask the user for a password to encode the private key
        while True:
            print("Please enter a password for the private key (leave blank for no password)", flush=True)
            pass1 = getpass()
            print("Please repeat your password", flush=True)
            pass2 = getpass()

            if pass1 == pass2:
                break
            else:
                print("Passwords do not match, please try again\n")

        # Generate the private key first
        privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        key_encr_algo = serialization.BestAvailableEncryption(bytes(pass1, "utf-8")) if len(pass1) > 0 else serialization.NoEncryption()

        # Save the private key with 600 permissions
        with open(root_pk_path, "wb") as f:
            f.write(privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=key_encr_algo
            ))

        os.chmod(root_pk_path, 0o600)

        # Now create the server's cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SE"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ACME"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        root_cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(privkey.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.utcnow()) \
            .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ) \
            .sign(privkey, hashes.SHA256(), default_backend())

        # Save the cert with 644 permissions
        with open(root_cert_path, "wb") as f:
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))

        os.chmod(root_cert_path, 0o644)

        # Load both into the module
        ROOT_CERTIFICATE = root_cert
        ROOT_KEY = privkey

    else:
        # Both the cert and the private key exist, load them
        printlog("Private key and certificate found, loading them.")

        # Load the private key
        with open(root_pk_path, "rb") as f:
            pk_bytes = f.read()

        try:
            key = load_pem_private_key(pk_bytes, None, default_backend())
        except TypeError:
            # The file is encrypted, ask the user for the password
            while True:
                print("Please, input the private key password:")
                pkpass = getpass()
                try:
                    key = load_pem_private_key(pk_bytes, bytes(pkpass, "utf-8"), default_backend())
                    break
                except ValueError:
                    print("The password is not correct, please try again.")

        # Load the cert
        with open(root_cert_path, "rb") as f:
            cert_bytes = f.read()

        ROOT_KEY = key
        ROOT_CERTIFICATE = x509.load_pem_x509_certificate(cert_bytes, default_backend())

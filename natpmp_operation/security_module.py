from datetime                                       import datetime, timedelta
from getpass                                        import getpass

from natpmp_operation.common_utils                  import printlog, get_future_date
from natpmp_operation.server_exceptions             import InvalidCertificateException, InvalidPacketSignatureException, MalformedPacketException

from cryptography                                   import x509
from cryptography.x509                              import DuplicateExtension, UnsupportedExtension, UnsupportedGeneralNameType, ExtensionNotFound
from cryptography.hazmat.backends                   import default_backend
from cryptography.hazmat.primitives                 import serialization, hashes
from cryptography.hazmat.primitives.asymmetric      import rsa, padding
from cryptography.hazmat.primitives.ciphers         import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization   import load_pem_private_key, load_der_private_key
from cryptography.x509.oid                          import NameOID, ExtensionOID
from cryptography.exceptions                        import InvalidSignature

from apscheduler.schedulers.background              import BackgroundScheduler
from apscheduler.triggers.date                      import DateTrigger

import os
import settings


CERT_CACHE_TIME = 30  # Seconds
ROOT_CERTIFICATE = None
ROOT_KEY = None

TLS_IPS = {}

# Initialize the scheduler that will take care of removing expired TLS IPs
enabled_ips_scheduler = BackgroundScheduler()
enabled_ips_scheduler.start()


# Loads the system root, self-signed cert into the module, creating it if it doesn't exist yet
def initialize_root_certificate():

    global ROOT_CERTIFICATE
    global ROOT_KEY

    root_cert_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "certs/root.crt")
    root_pk_path = os.path.join(os.path.dirname(root_cert_path), "root.key")

    if os.path.exists(root_cert_path) and os.path.exists(root_pk_path):

        # Both the cert and the private key exist, load them
        ROOT_KEY = load_private_key_asking_for_password(root_pk_path, "Please, input the password for the root private key:")
        ROOT_CERTIFICATE = load_certificate(root_cert_path)

    else:
        # Must create a new cert-key pair
        printlog("Root certificate and/or private key not found, creating new ones...")

        # Ask the user for a password to encode the private key
        while True:
            print("Please enter a password for the root private key (leave blank for no password)", flush=True)
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

        # Now create the server's cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SE"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ACME"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"NAT-PMP Daemon"),
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
        ).sign(privkey, hashes.SHA256(), default_backend())

        # Save the cert with 644 permissions
        with open(root_cert_path, "wb") as f:
            f.write(root_cert.public_bytes(serialization.Encoding.DER))

        os.chmod(root_cert_path, 0o644)

        # Save the private key with 600 permissions
        with open(root_pk_path, "wb") as f:
            f.write(privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=key_encr_algo
            ))

        os.chmod(root_pk_path, 0o600)

        # Load both into the module
        ROOT_CERTIFICATE = root_cert
        ROOT_KEY = privkey


# Given a bytes object, returns a valid certificate or raises InvalidCertificateException otherwise.
# Note that if strict certificate checking is enabled, only certificates issued by the get-cert
# utility will be considered valid.
def get_cert_from_bytes(byte_data):

    # Try to decode the cert from the byte data
    try:
        cert = x509.load_pem_x509_certificate(byte_data, default_backend())
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(byte_data, default_backend())
        except ValueError:
            raise InvalidCertificateException("The certificate is sintactically incorrect or it's not in any supported encodings (PEM/DER)")

    # We got the cert and it seems to be correct, check that the current time is within the boundaries
    if not cert.not_valid_before < datetime.utcnow() < cert.not_valid_after:
        raise InvalidCertificateException("The certificate is expired or not yet active")

    # If strict checking is enabled, check that it is signed by our root certificate and key
    if settings.STRICT_CERTIFICATE_CHECKING:
        cert_payload_bytes = cert.tbs_certificate_bytes
        cert_hashing_algo = cert.signature_hash_algorithm
        cert_signature = cert.signature
        root_cert_public_key = ROOT_CERTIFICATE.public_key()

        try:
            root_cert_public_key.verify(
                cert_signature,
                cert_payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(cert_hashing_algo),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                cert_hashing_algo
            )
        except InvalidSignature:
            raise InvalidCertificateException("The certificate was not issued by the NAT-PMP service.")

    return cert


# Checks if a certificate is issued for a specific IP address
def is_cert_valid_for_ip(cert, ip):

    # First, check if the IP is in the cert's common name field
    cnames = [n.value for n in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]

    if ip in cnames:
        return True

    # If it's not there, check if it is in the cert's alternative names in the extensions
    try:
        cert_extensions = cert.extensions
    except (DuplicateExtension, UnsupportedExtension, UnsupportedGeneralNameType, UnicodeError):
        # The extensions encoded in this cert are not valid
        return False

    # Grab the 'alternative names names' extension
    try:
        altnames_ext = cert_extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
    except ExtensionNotFound:
        # The cert does not have such extension
        return False

    # Return True if the address is in the alternative names list, False otherwise
    return ip in [dns.value for dns in altnames_ext.value]


# Signs byte_data using private_key and ciphers the data using public_key
# Data is returned as per NAT-PMP custom v1 specification

def sign_and_cipher_data_with_nonce(byte_data, public_key, private_key, nonce):

    if type(byte_data) is bytearray:
        byte_data = bytes(byte_data)

    # Prepend the nonce to the data to be signed
    data_to_sign = nonce + byte_data

    # Sign the data with the nonce
    signature = private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )

    # Will cipher using AES both the data and the signature
    data_to_cipher = signature + nonce + byte_data

    # Add padding until the plain data is congruent with 120 bytes, then prepend the amount of padded bytes
    padding_amount = 0
    while len(data_to_cipher) % 16 != 15:
        padding_amount += 1
        data_to_cipher += bytes(1)

    data_to_cipher = padding_amount.to_bytes(1, 'big') + data_to_cipher

    aes_key = os.urandom(16)
    aes_iv = os.urandom(16)

    # Cipher the data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphered_data = encryptor.update(data_to_cipher) + encryptor.finalize()

    # Cipher the AES key with RSA
    ciphered_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send the AES IV, the ciphered key and the ciphered data
    return aes_iv + ciphered_key + ciphered_data


# Deciphers ciphered using private_key and checks the signature against public_key as well as the nonce
def decipher_and_check_signature_and_nonce(ciphered, private_key, public_key, nonce):

    if type(ciphered) is bytearray:
        ciphered = bytes(ciphered)

    if len(ciphered) < 30:
        raise MalformedPacketException("Ciphered packet is too short")

    signature_size = get_encoded_length(public_key)
    encoded_size = get_encoded_length(private_key)

    # Get the AES IV, the first 16 bytes
    aes_iv = ciphered[0:16]

    # Get the cipherred AES key
    ciphered_aes_key = ciphered[16:16+encoded_size]

    # Get the AES-ciphered data
    ciphered_data = ciphered[16+encoded_size:]

    # Decipher the AES key
    aes_key = private_key.decrypt(
        ciphered_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decipher the data
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain_data = decryptor.update(ciphered_data) + decryptor.finalize()

    # Get the padding amount, signature, nonce and plain request
    padded_amount = plain_data[0]
    signature = plain_data[1:signature_size+1]
    sent_nonce = plain_data[signature_size+1:signature_size+9]
    request = plain_data[signature_size+9:len(plain_data) - padded_amount]

    # Check that the nonce matches
    if nonce != sent_nonce:
        raise MalformedPacketException("The nonces do not match.")

    # Check the signature
    try:
        public_key.verify(
            signature,
            sent_nonce + request,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise InvalidPacketSignatureException("The received packet's signature is not valid.")

    return request

##########################################################################################################
##########################################################################################################
##########################################################################################################


def add_ip_to_tls_enabled(ip_addr, cert, nonce):
    autoremoval_trigger = DateTrigger(get_future_date(CERT_CACHE_TIME))

    # If it's already in the dict, update the removal time
    if ip_addr in TLS_IPS:
        TLS_IPS[ip_addr]['job'].reschedule(autoremoval_trigger)
        printlog("Renewing %s in TLS-enabled IPs" % ip_addr)
    else:
        job = enabled_ips_scheduler.add_job(remove_ip_from_tls_enabled, trigger=autoremoval_trigger, args=(ip_addr, True))
        TLS_IPS[ip_addr] = {'cert': cert, 'job': job, 'nonce': nonce}
        printlog("Adding %s to TLS-enabled IPs" % ip_addr)


def remove_ip_from_tls_enabled(ip_addr, auto=False):
    if ip_addr in TLS_IPS:
        if not auto:
            TLS_IPS[ip_addr]['job'].remove()
        del TLS_IPS[ip_addr]

        logtext = "Removing %s from TLS-enabled IPs" % ip_addr
        if auto:
            logtext += " (timed out)"
        printlog(logtext)

##########################################################################################################
##########################################################################################################
##########################################################################################################
# Utility functions for loading private keys and certs


# Load a private key in PEM or DER format
# Raises ValueError if the password is not correct
def load_private_key(keypath, password):

    # Load the private key
    with open(keypath, "rb") as f:
        pk_bytes = f.read()

    passbytes = None if password is None else bytes(password, "utf-8")

    # Try to decode it in both formats with the provided password
    try:
        key = load_pem_private_key(pk_bytes, passbytes, default_backend())
    except ValueError:
        # The key could not be decoded, try in DER
        try:
            key = load_der_private_key(pk_bytes, passbytes, default_backend())
        except TypeError:
            # The password is not correct
            raise ValueError
    except TypeError:
        # The password is not correct
        raise ValueError

    return key


# Loads a private key, asking repeteadly for a password via console if it's encrypted
def load_private_key_asking_for_password(keypath, msg="Please input the password for the private key:"):
    try:
        return load_private_key(keypath, None)
    except ValueError:
        print(msg, flush=True)
        while True:
            passw = getpass()
            try:
                return load_private_key(keypath, passw)
            except ValueError:
                print("Password is not correct, please try again.", flush=True)


# Load a certificate in PEM or DER format
# Raises ValueError if its not valid
def load_certificate(certpath):

    # Load the private key
    with open(certpath, "rb") as f:
        byte_data = f.read()

    # Try to decode the cert from the byte data
    try:
        cert = x509.load_pem_x509_certificate(byte_data, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(byte_data, default_backend())

    return cert


def get_encoded_length(key):
    # Returns the length in bytes for encoded data and signatures in RSA (EC not supported)
    try:
        return key.key_size // 8
    except AttributeError:
        raise MalformedPacketException("Asymmetric algorithm not currently supported")

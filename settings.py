PRIVATE_INTERFACES = [
    "10.0.0.1",
    "192.168.0.1",
]

PUBLIC_INTERFACES = [
    "80.102.236.61",
]

ALLOW_VERSION_0 = True
ALLOW_VERSION_1 = True

ALLOW_TLS_IN_V1 = True
FORCE_TLS_IN_V1 = False
STRICT_CERTIFICATE_CHECKING = False

MIN_ALLOWED_MAPPABLE_PORT = 1
MAX_ALLOWED_MAPPABLE_PORT = 65535
EXCLUDED_PORTS = [80, 443, 8080]

MIN_ALLOWED_LIFETIME = 60  # Seconds
MAX_ALLOWED_LIFETIME = 3600  # Seconds

FIXED_LIFETIME = None  # In seconds, set to a value to force all mappings lifetime to this value

BLACKLIST_MODE = True
BLACKLISTED_IPS = [
    "10.0.13.37",
    "192.168.10.12",
]

WHITELIST_MODE = False
WHITELISTED_IPS = [
    "10.14.33.12",
    "192.168.55.123",
]

DEBUG = False  # If set to True, will print the current state of all mappings after every request.

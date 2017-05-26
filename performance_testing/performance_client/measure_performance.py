from .parse_commands import get_namespace
from natpmp_operation.natpmp_logic_common import NATPMP_OPCODE_INFO, NATPMP_OPCODE_MAPUDP

if __name__ == "__main__":
    namespace = get_namespace()

    version = namespace.v
    reqs_to_send = namespace.n
    operation = NATPMP_OPCODE_INFO if namespace.op == "info" else NATPMP_OPCODE_MAPUDP
    ips = namespace.ips
    use_tls = bool(namespace.sec)
    if use_tls:
        cert = namespace.sec[0]
        key = namespace.key[1]

import asyncio
import logging
import socket
import struct
import os

log = logging.getLogger(__name__)

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_MAGIC_COOKIE = 0x2112A442
MAPPED_ADDRESS = 0x0001
XOR_MAPPED_ADDRESS = 0x0020


def _build_binding_request() -> tuple[bytes, bytes]:
    transaction_id = os.urandom(12)
    header = struct.pack(
        "!HHI12s",
        STUN_BINDING_REQUEST,
        0,
        STUN_MAGIC_COOKIE,
        transaction_id,
    )
    return header, transaction_id


def _parse_response(data: bytes, transaction_id: bytes) -> tuple[str, int] | None:
    if len(data) < 20:
        return None

    msg_type, msg_len, magic, tid = struct.unpack("!HHI12s", data[:20])

    if msg_type != STUN_BINDING_RESPONSE:
        return None
    if magic != STUN_MAGIC_COOKIE:
        return None
    if tid != transaction_id:
        return None

    offset = 20
    while offset < 20 + msg_len:
        if offset + 4 > len(data):
            break
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        attr_value = data[offset + 4: offset + 4 + attr_len]
        offset += 4 + attr_len + (attr_len % 4 and 4 - attr_len % 4 or 0)

        if attr_type == XOR_MAPPED_ADDRESS and len(attr_value) >= 8:
            port = struct.unpack("!H", attr_value[2:4])[0] ^ (STUN_MAGIC_COOKIE >> 16)
            ip_int = struct.unpack("!I", attr_value[4:8])[0] ^ STUN_MAGIC_COOKIE
            ip = socket.inet_ntoa(struct.pack("!I", ip_int))
            return ip, port

        elif attr_type == MAPPED_ADDRESS and len(attr_value) >= 8:
            port = struct.unpack("!H", attr_value[2:4])[0]
            ip = socket.inet_ntoa(attr_value[4:8])
            return ip, port

    return None


class StunResult:
    def __init__(self, external_ip: str, external_port: int, stun_server: str):
        self.external_ip = external_ip
        self.external_port = external_port
        self.stun_server = stun_server

    def __repr__(self):
        return f"StunResult({self.external_ip}:{self.external_port} via {self.stun_server})"


async def discover_external_address(
    local_port: int,
    timeout: float = 3.0,
) -> StunResult | None:

    loop = asyncio.get_running_loop()

    for host, port in STUN_SERVERS:
        sock = None
        try:
            infos = await loop.getaddrinfo(
                host, port,
                type=socket.SOCK_DGRAM,
                proto=socket.IPPROTO_UDP,
            )
            if not infos:
                continue
            _, _, _, _, server_addr = infos[0]

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            try:
                sock.bind(("", local_port))
            except OSError:
                sock.bind(("", 0))

            packet, tid = _build_binding_request()
            await loop.sock_sendto(sock, packet, server_addr)

            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 1024),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                log.debug("[STUN] %s:%d timed out", host, port)
                continue

            result = _parse_response(data, tid)
            if result:
                ext_ip, ext_port = result
                log.info("[STUN] External address: %s:%d (via %s)", ext_ip, ext_port, host)
                return StunResult(ext_ip, ext_port, host)

        except Exception as e:
            log.debug("[STUN] %s:%d error: %s", host, port, e)
        finally:
            if sock:
                sock.close()

    log.warning("[STUN] All servers failed or timed out")
    return None

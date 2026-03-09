import asyncio
import socket
import logging
from typing import Callable, Optional

from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceStateChange
from zeroconf.asyncio import AsyncZeroconf

SERVICE_TYPE = "_p2pchat._tcp.local."

log = logging.getLogger(__name__)


def _local_ip() -> str:
    """Best-effort: find the LAN IP of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class MDNSDiscovery:
    """
    Registers this node on the LAN via mDNS and notifies the caller
    when other p2p-chat nodes appear or disappear.

    on_found(peer_id, host, port) — called when a new peer is discovered.
    on_lost(peer_id)              — called when a peer goes offline.
    """

    def __init__(
        self,
        peer_id: str,
        name: str,
        port: int,
        on_found: Optional[Callable[[str, str, int], None]] = None,
        on_lost: Optional[Callable[[str], None]] = None,
    ):
        self.peer_id = peer_id
        self.name = name
        self.port = port
        self.host = _local_ip()
        self.on_found = on_found
        self.on_lost = on_lost

        self._loop = None
        self._azc: Optional[AsyncZeroconf] = None
        self._info: Optional[ServiceInfo] = None
        self._browser = None

    def _make_service_info(self) -> ServiceInfo:
        # Service name must be unique on the LAN — use peer_id as prefix.
        service_name = f"{self.peer_id[:12]}.{self.name}.{SERVICE_TYPE}"
        return ServiceInfo(
            type_=SERVICE_TYPE,
            name=service_name,
            addresses=[socket.inet_aton(self.host)],
            port=self.port,
            properties={
                "peer_id": self.peer_id,
                "name": self.name,
                "v": "1",
            },
            server=f"{self.peer_id[:12]}.local.",
        )

    async def start(self):
        # Save the running loop so we can safely call it from zeroconf's thread.
        self._loop = asyncio.get_running_loop()

        self._azc = AsyncZeroconf()
        self._info = self._make_service_info()

        await self._azc.async_register_service(self._info)
        log.info("[mDNS] Registered as %s on %s:%d", self._info.name, self.host, self.port)

        # ServiceBrowser is synchronous internally but thread-safe with zeroconf.
        self._browser = ServiceBrowser(
            self._azc.zeroconf,
            SERVICE_TYPE,
            handlers=[self._on_service_state_change],
        )

    async def stop(self):
        if self._azc is None:
            return
        if self._info:
            await self._azc.async_unregister_service(self._info)
        await self._azc.async_close()
        log.info("[mDNS] Stopped")

    def _on_service_state_change(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ):
        if state_change == ServiceStateChange.Added:
            self._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self._handle_added(zeroconf, service_type, name))
            )
        elif state_change == ServiceStateChange.Removed:
            self._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self._handle_removed(zeroconf, service_type, name))
            )

    async def _handle_added(self, zeroconf: Zeroconf, service_type: str, name: str):
        info = ServiceInfo(service_type, name)
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: info.request(zeroconf, 3000)
        )

        if not info.addresses:
            return

        props = {
            k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
            for k, v in (info.properties or {}).items()
        }

        remote_peer_id = props.get("peer_id", "")
        if not remote_peer_id or remote_peer_id == self.peer_id:
            return  # own announcement, skip

        host = socket.inet_ntoa(info.addresses[0])
        port = info.port

        log.info("[mDNS] Found peer %s at %s:%d", remote_peer_id[:12], host, port)

        if self.on_found:
            self.on_found(remote_peer_id, host, port)

    async def _handle_removed(self, zeroconf: Zeroconf, service_type: str, name: str):
        # Extract peer_id prefix from service name (first segment before first dot)
        peer_id_prefix = name.split(".")[0]
        log.info("[mDNS] Lost peer %s...", peer_id_prefix)

        if self.on_lost:
            self.on_lost(peer_id_prefix)
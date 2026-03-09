import argparse
import asyncio
import logging

from peer import PeerNode
from identity import load_or_create_identity
from qr_contact import make_contact_card, validate_and_parse, print_ascii_qr
from contacts import load_contacts, save_contacts, upsert_contact, get_contact
from discovery import MDNSDiscovery
from stun import discover_external_address
from nacl.encoding import Base64Encoder

logging.basicConfig(level=logging.INFO, format="%(message)s")


async def run_server(name: str, host: str, port: int, enable_mdns: bool):
    sk, vk, peer_id = load_or_create_identity()
    node = PeerNode(name)

    print("[STUN] Discovering external address...")
    stun = await discover_external_address(local_port=port)
    if stun:
        print(f"[STUN] Your external address: {stun.external_ip}:{stun.external_port}")
        print(f"       Share this in your contact card for internet connections.")
        print(f"       (Only works if port {port} is forwarded on your router)")
    else:
        print("[STUN] Could not determine external address (no internet or blocked)")

    mdns = None
    if enable_mdns:
        mdns = MDNSDiscovery(
            peer_id=peer_id,
            name=name,
            port=port,
            on_found=lambda pid, h, p: asyncio.ensure_future(
                _try_connect(node, pid, h, p)
            ),
        )
        await mdns.start()
        print(f"[mDNS] Announced on LAN as '{name}' ({peer_id[:12]}...)")

    server = await asyncio.start_server(node.handle_connection, host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[{name}] Listening on {addrs}")

    try:
        async with server:
            await server.serve_forever()
    finally:
        if mdns:
            await mdns.stop()


async def run_client(name: str, host: str, port: int, remote_hint: str, enable_mdns: bool):
    sk, vk, peer_id = load_or_create_identity()
    node = PeerNode(name)

    mdns = None
    if enable_mdns:
        mdns = MDNSDiscovery(
            peer_id=peer_id,
            name=name,
            port=port,
            on_found=lambda pid, h, p: asyncio.ensure_future(
                _try_connect(node, pid, h, p)
            ),
        )
        await mdns.start()
        print(f"[mDNS] Listening for peers on LAN...")

    try:
        await node.connect_to(host, port, remote_hint)
    finally:
        if mdns:
            await mdns.stop()


async def _try_connect(node: PeerNode, peer_id: str, host: str, port: int):
    """Connect to a peer discovered via mDNS only if they are a known contact."""
    from peer import State
    if node.state not in (State.DISCONNECTED, State.CLOSED):
        return

    db = load_contacts()
    contact = get_contact(db, peer_id)
    if contact is None:
        print(f"[mDNS] Discovered unknown peer {peer_id[:12]}... — not in contacts, skipping")
        return

    print(f"[mDNS] Auto-connecting to known contact '{contact.get('name', peer_id[:12])}' at {host}:{port}")
    try:
        await node.connect_to(host, port, peer_id)
    except (OSError, ConnectionResetError):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)

    ap.add_argument("--qr", action="store_true",
                    help="Print contact card JSON + ASCII QR and exit")
    ap.add_argument("--import-card", dest="import_card", type=str, default="",
                    help="Import contact card JSON (string) and exit")
    ap.add_argument("--import-card-file", dest="import_card_file", type=str, default="",
                    help="Import contact card from file and exit (recommended)")

    ap.add_argument("--listen", action="store_true", help="Run as server")
    ap.add_argument("--host", default="0.0.0.0",
                    help="Bind address for --listen, or target host for --connect")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--connect", action="store_true", help="Run as client")
    ap.add_argument("--to", default="*", help="Target peer_id hint (optional)")
    ap.add_argument("--no-mdns", action="store_true",
                    help="Disable mDNS LAN discovery")

    args = ap.parse_args()

    if args.qr:
        sk, vk, peer_id = load_or_create_identity()
        ik_pub_b64 = vk.encode(encoder=Base64Encoder).decode()
        host_hint = args.host if args.host != "0.0.0.0" else "127.0.0.1"
        data = make_contact_card(peer_id, ik_pub_b64, args.name, host_hint, args.port)
        print(data)
        print_ascii_qr(data)
        return

    if args.import_card_file:
        with open(args.import_card_file, "r", encoding="utf-8-sig") as f:
            card_text = f.read()
        card = validate_and_parse(card_text)
        db = load_contacts()
        upsert_contact(db, card["peer_id"], card["ik_pub"], card.get("name", ""), trust="TRUSTED")
        save_contacts(db)
        print(f"Imported TRUSTED contact: {card.get('name', '')} ({card['peer_id'][:12]}...)")
        return

    if args.import_card:
        card = validate_and_parse(args.import_card)
        db = load_contacts()
        upsert_contact(db, card["peer_id"], card["ik_pub"], card.get("name", ""), trust="TRUSTED")
        save_contacts(db)
        print(f"Imported TRUSTED contact: {card.get('name', '')} ({card['peer_id'][:12]}...)")
        return

    if args.listen == args.connect:
        raise SystemExit("Choose exactly one: --listen or --connect")

    enable_mdns = not args.no_mdns

    if args.listen:
        asyncio.run(run_server(args.name, args.host, args.port, enable_mdns))
    else:
        asyncio.run(run_client(args.name, args.host, args.port, args.to, enable_mdns))


if __name__ == "__main__":
    main()
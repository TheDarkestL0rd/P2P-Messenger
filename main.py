import argparse
import asyncio

from peer import PeerNode
from identity import load_or_create_identity
from qr_contact import make_contact_card, validate_and_parse, print_ascii_qr
from contacts import load_contacts, save_contacts, upsert_contact
from nacl.encoding import Base64Encoder


async def run_server(name: str, host: str, port: int):
    node = PeerNode(name)
    server = await asyncio.start_server(node.handle_connection, host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[{name}] listening on {addrs}")
    async with server:
        await server.serve_forever()


async def run_client(name: str, host: str, port: int, remote_hint: str):
    node = PeerNode(name)
    await node.connect_to(host, port, remote_hint)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)

    ap.add_argument("--qr", action="store_true", help="Print contact card JSON + ASCII QR and exit")
    ap.add_argument("--import-card", dest="import_card", type=str, default="",
                    help="Import contact card JSON (string) and exit (PowerShell pain)")
    ap.add_argument("--import-card-file", dest="import_card_file", type=str, default="",
                    help="Import contact card from file and exit (recommended)")

    ap.add_argument("--listen", action="store_true", help="Run as server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--connect", action="store_true", help="Run as client")
    ap.add_argument("--to", default="*")

    args = ap.parse_args()

    if args.qr:
        sk, vk, peer_id = load_or_create_identity()
        ik_pub_b64 = vk.encode(encoder=Base64Encoder).decode()
        data = make_contact_card(peer_id, ik_pub_b64, args.name, args.host, args.port)
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
        print(f"Imported TRUSTED contact: {card.get('name','')} {card['peer_id']}")
        return

    if args.import_card:
        card = validate_and_parse(args.import_card)
        db = load_contacts()
        upsert_contact(db, card["peer_id"], card["ik_pub"], card.get("name", ""), trust="TRUSTED")
        save_contacts(db)
        print(f"Imported TRUSTED contact: {card.get('name','')} {card['peer_id']}")
        return

    if args.listen == args.connect:
        raise SystemExit("Choose exactly one: --listen or --connect")

    if args.listen:
        asyncio.run(run_server(args.name, args.host, args.port))
    else:
        asyncio.run(run_client(args.name, args.host, args.port, args.to))


if __name__ == "__main__":
    main()
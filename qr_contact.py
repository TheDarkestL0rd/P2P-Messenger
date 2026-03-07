import json
import hashlib

def make_contact_card(peer_id: str, ik_pub_b64: str, name: str, host: str = "", port: int = 0) -> str:
    card = {
        "v": 1,
        "peer_id": peer_id,
        "ik_pub": ik_pub_b64,
        "name": name,
        "hint": {"host": host, "port": port}
    }
    return json.dumps(card, ensure_ascii=False)

def validate_and_parse(card_json: str) -> dict:
    card_json = card_json.lstrip("\ufeff").strip()
    card = json.loads(card_json)

    ik_pub_b64 = card["ik_pub"]
    peer_id_check = hashlib.sha256(ik_pub_b64.encode("utf-8")).hexdigest()
    if peer_id_check != card["peer_id"]:
        raise ValueError("Invalid card: peer_id != sha256(ik_pub)")
    return card

def print_ascii_qr(data: str):
    import sys
    import qrcode

    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)

    try:
        qr.print_ascii(out=sys.stderr, invert=True)
    except UnicodeEncodeError:
        m = qr.get_matrix()
        for row in m:
            line = "".join("##" if cell else "  " for cell in row)
            sys.stderr.write(line + "\n")
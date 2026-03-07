from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder
import os
import json
import hashlib

IDENTITY_FILE = "identity.json"

def load_or_create_identity():
    if os.path.exists(IDENTITY_FILE):
        with open(IDENTITY_FILE, "r") as f:
            data = json.load(f)
        signing_key = SigningKey(data["priv"], encoder=Base64Encoder)
    else:
        signing_key = SigningKey.generate()
        with open(IDENTITY_FILE, "w") as f:
            json.dump({
                "priv": signing_key.encode(encoder=Base64Encoder).decode()
            }, f)

    verify_key = signing_key.verify_key
    pubkey = verify_key.encode(encoder=Base64Encoder)
    peer_id = hashlib.sha256(pubkey).hexdigest()

    return signing_key, verify_key, peer_id
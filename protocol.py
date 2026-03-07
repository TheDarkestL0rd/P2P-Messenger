import json
import time
import secrets
import uuid
from typing import Any, Dict

def now_ts() -> int:
    return int(time.time())

def new_nonce(nbytes: int = 12) -> str:
    return secrets.token_hex(nbytes)

def new_msg_id() -> str:
    return str(uuid.uuid4())

def encode_msg(msg: Dict[str, Any]) -> bytes:
    return (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")

def decode_line(line: bytes) -> Dict[str, Any]:
    return json.loads(line.decode("utf-8"))

def make_hello(frm: str, to: str) -> Dict[str, Any]:
    return {
        "v": 1,
        "type": "HELLO",
        "from": frm,
        "to": to,
        "ts": now_ts(),
        "nonce": new_nonce(),
        "payload": {"features": ["chat_v0"]}
    }

def make_msg(frm: str, to: str, text: str, seq: int) -> Dict[str, Any]:
    return {
        "v": 1,
        "type": "MSG",
        "from": frm,
        "to": to,
        "ts": now_ts(),
        "nonce": new_nonce(),
        "payload": {
            "msg_id": new_msg_id(),
            "seq": seq,
            "text": text
        }
    }

def make_ack(frm: str, to: str, msg_id: str, seq: int, status: str = "ok") -> Dict[str, Any]:
    return {
        "v": 1,
        "type": "ACK",
        "from": frm,
        "to": to,
        "ts": now_ts(),
        "nonce": new_nonce(),
        "payload": {
            "ack_id": msg_id,
            "seq": seq,
            "status": status
        }
    }